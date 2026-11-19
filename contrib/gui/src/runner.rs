//! Finds and runs the `netdoc` program.

use crate::report::{self, Outcome};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

/// How much of netdoc's error output to keep.
const STDERR_KEEP: usize = 8 * 1024;

pub enum Msg {
    Report(Outcome),
    Finished { code: Option<i32>, stderr: String },
    Failed(String),
    Saved(Result<PathBuf, String>),
}

/// The program's file name: `netdoc`, or `netdoc.exe` on Windows.
fn netdoc_name() -> String {
    format!("netdoc{}", std::env::consts::EXE_SUFFIX)
}

/// netdoc next to our own binary (a bundle can ship it there), then $NETDOC, then PATH.
/// Only absolute paths count: an empty or relative PATH entry means "the
/// current folder", where anyone who can drop a file named netdoc would win.
pub fn find_netdoc() -> Option<PathBuf> {
    let usable = |p: &Path| p.is_absolute() && p.is_file();
    if let Ok(exe) = std::env::current_exe() {
        let p = exe.with_file_name(netdoc_name());
        if usable(&p) {
            return Some(p);
        }
    }
    if let Some(p) = std::env::var_os("NETDOC").map(PathBuf::from)
        && usable(&p)
    {
        return Some(p);
    }
    let path = std::env::var_os("PATH")?;
    find_in_path(&path)
}

fn find_in_path(path: &std::ffi::OsStr) -> Option<PathBuf> {
    std::env::split_paths(path)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(netdoc_name()))
        .find(|p| p.is_file())
}

/// A netdoc command. On Linux it dies with us: if the GUI crashes or is
/// killed, the kernel stops netdoc too, so `--watch` can't keep probing in the
/// background with nobody looking. Elsewhere a normal close still stops it
/// (see `Drop for App`), but a crash does not. On Windows it runs without a
/// console window of its own.
fn netdoc_command(bin: &Path) -> Command {
    // Only Linux and Windows change the command below.
    #[cfg_attr(not(any(target_os = "linux", windows)), allow(unused_mut))]
    let mut cmd = Command::new(bin);
    #[cfg(target_os = "linux")]
    die_with_parent(&mut cmd);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

#[cfg(target_os = "linux")]
fn die_with_parent(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    let parent = std::process::id() as libc::pid_t;
    // SAFETY: only async-signal-safe libc calls between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // The GUI may already have gone between fork and prctl.
            if libc::getppid() != parent {
                libc::_exit(0);
            }
            Ok(())
        });
    }
}

pub fn version(bin: &Path) -> Option<String> {
    let out = netdoc_command(bin).arg("--version").output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// A running diagnosis that can be stopped.
#[derive(Clone, Default)]
pub struct Handle(Arc<Mutex<Option<Child>>>);

impl Handle {
    pub fn stop(&self) {
        if let Some(c) = self.0.lock().unwrap().as_mut() {
            let _ = c.kill();
        }
    }
}

/// Run `netdoc --json [--profile NAME] [--watch] [target]`. One report per line in watch mode.
pub fn run(
    bin: PathBuf,
    profile: Option<String>,
    target: Option<String>,
    watch: Option<u32>,
    tx: Sender<Msg>,
    wake: impl Fn() + Send + 'static,
) -> Handle {
    let handle = Handle::default();
    let h = handle.clone();
    std::thread::spawn(move || {
        let mut cmd = netdoc_command(&bin);
        cmd.arg("--json");
        if let Some(p) = &profile {
            cmd.arg("--profile").arg(p);
        }
        if let Some(secs) = watch {
            cmd.arg("--watch")
                .arg("--watch-interval")
                .arg(format!("{secs}s"));
        }
        if let Some(t) = &target {
            // "--" so a target can never be read as an option.
            cmd.arg("--").arg(t);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.send(Msg::Failed(format!("Couldn't start netdoc: {e}")));
                wake();
                return;
            }
        };
        let stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        *h.0.lock().unwrap() = Some(child);
        // Only the end of the error output is kept: a long watch can't
        // grow it without limit, and the last lines are the useful ones.
        let err_thread = std::thread::spawn(move || {
            let mut kept: Vec<u8> = Vec::new();
            let mut buf = [0u8; 4096];
            while let Ok(n) = stderr.read(&mut buf) {
                if n == 0 {
                    break;
                }
                kept.extend_from_slice(&buf[..n]);
                if kept.len() > 2 * STDERR_KEEP {
                    kept.drain(..kept.len() - STDERR_KEEP);
                }
            }
            if kept.len() > STDERR_KEEP {
                kept.drain(..kept.len() - STDERR_KEEP);
            }
            String::from_utf8_lossy(&kept).into_owned()
        });
        if watch.is_some() {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if line.trim().is_empty() {
                    continue;
                }
                match report::parse(&line) {
                    Ok(r) => {
                        let _ = tx.send(Msg::Report(r));
                        wake();
                    }
                    Err(e) => {
                        // Stop netdoc for real, so "stopped" on screen is true.
                        h.stop();
                        let _ = tx.send(Msg::Failed(e));
                        wake();
                        break;
                    }
                }
            }
        } else {
            let mut s = String::new();
            let _ = BufReader::new(stdout).read_to_string(&mut s);
            if !s.trim().is_empty() {
                let _ = tx.send(match report::parse(&s) {
                    Ok(r) => Msg::Report(r),
                    Err(e) => Msg::Failed(e),
                });
            }
        }
        let code =
            h.0.lock()
                .unwrap()
                .take()
                .and_then(|mut c| c.wait().ok())
                .and_then(|s| s.code());
        let stderr = err_thread.join().unwrap_or_default();
        let _ = tx.send(Msg::Finished { code, stderr });
        wake();
    });
    handle
}

/// `netdoc --support FILE [target]`: the privacy-conscious report for sharing.
pub fn save_support(
    bin: PathBuf,
    profile: Option<String>,
    target: Option<String>,
    dest: PathBuf,
    tx: Sender<Msg>,
    wake: impl Fn() + Send + 'static,
) {
    std::thread::spawn(move || {
        // Never replace a file that's already there.
        let dest = unused_name(dest);
        let mut cmd = netdoc_command(&bin);
        cmd.arg("--support").arg(&dest);
        if let Some(p) = &profile {
            cmd.arg("--profile").arg(p);
        }
        if let Some(t) = &target {
            cmd.arg("--").arg(t);
        }
        let res = match cmd.stdin(Stdio::null()).output() {
            // 0 = healthy, 1 = a problem was found; both write the file.
            // Anything else (2 = usage or write error) means it didn't.
            Ok(out) if matches!(out.status.code(), Some(0) | Some(1)) && dest.is_file() => Ok(dest),
            Ok(out) => Err(format!(
                "netdoc didn't write the report: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )),
            Err(e) => Err(format!("Couldn't start netdoc: {e}")),
        };
        let _ = tx.send(Msg::Saved(res));
        wake();
    });
}

/// `name.ndoc`, or `name-2.ndoc`, `name-3.ndoc`… if that's taken.
fn unused_name(dest: PathBuf) -> PathBuf {
    if !dest.exists() {
        return dest;
    }
    let stem = dest
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    (2..)
        .map(|n| dest.with_file_name(format!("{stem}-{n}.ndoc")))
        .find(|p| !p.exists())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_lookup_ignores_the_current_folder() {
        let dir = std::env::temp_dir().join(format!("netdoc-gui-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(netdoc_name()), "planted").unwrap();
        let old = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        // An empty entry and a relative one both mean "here".
        let found = find_in_path(std::ffi::OsStr::new(":.:/nonexistent-dir"));
        std::env::set_current_dir(old).unwrap();
        // The planted file must not be found; an absolute dir must still work.
        assert_eq!(found, None);
        assert_eq!(find_in_path(dir.as_os_str()), Some(dir.join(netdoc_name())));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn export_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("netdoc-gui-names-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("r.ndoc");
        assert_eq!(unused_name(a.clone()), a);
        std::fs::write(&a, "x").unwrap();
        assert_eq!(unused_name(a.clone()), dir.join("r-2.ndoc"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
