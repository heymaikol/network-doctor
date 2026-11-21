//! Finds and runs the `netdoc` program.

use crate::report::{self, Outcome};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

/// A running netdoc that can be stopped. `stop` works at any time: a child
/// that isn't attached yet is stopped as soon as it is.
#[derive(Clone, Default)]
pub struct Handle(Arc<Mutex<Slot>>);

#[derive(Default)]
struct Slot {
    child: Option<Child>,
    stopped: bool,
    /// Set when netdoc was stopped for running too long, not at the user's request.
    expired: Option<&'static str>,
}

/// How long netdoc gets to exit after a stop, before it is killed.
const STOP_GRACE: Duration = Duration::from_secs(3);

/// How long netdoc gets to exit after its output has ended.
const EXIT_GRACE: Duration = Duration::from_secs(5);

const CLOSED_OUTPUT: &str = "netdoc closed its output but didn't exit, so it was stopped.";

/// How long a one-shot check or export may run. netdoc budgets its worst-case
/// pass at 20 s, so two minutes means it is hung. Watch mode has no limit: Stop ends it.
const RUN_LIMIT: Duration = Duration::from_secs(120);

const TOO_LONG: &str = "netdoc didn't finish within two minutes, so it was stopped.";

/// Stops netdoc for running out of time. A stop the user asked for comes first and wins.
fn expire_locked(s: &mut Slot, reason: &'static str) {
    if s.stopped {
        return;
    }
    s.stopped = true;
    s.expired = Some(reason);
    if let Some(c) = s.child.as_mut() {
        ask_to_stop(c);
    }
}

/// SIGTERM on Unix, which netdoc answers by cancelling its probes and removing
/// its temporary files. Windows has no such signal, so the process is ended.
fn ask_to_stop(child: &mut Child) {
    #[cfg(unix)]
    {
        // SAFETY: the child is attached and not yet reaped, so its id is still its own.
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
}

impl Handle {
    pub fn stop(&self) {
        let mut s = self.0.lock().unwrap();
        s.stopped = true;
        if let Some(c) = s.child.as_mut() {
            ask_to_stop(c);
        }
    }

    fn stopped(&self) -> bool {
        self.0.lock().unwrap().stopped
    }

    /// Hands the started child over. A stop asked for before this applies now.
    fn attach(&self, mut child: Child) {
        let mut s = self.0.lock().unwrap();
        if s.stopped {
            ask_to_stop(&mut child);
        }
        s.child = Some(child);
    }

    /// Stops netdoc for running out of time, with the reason the window shows.
    fn expire(&self, reason: &'static str) {
        expire_locked(&mut self.0.lock().unwrap(), reason);
    }

    /// Why netdoc was stopped for running out of time, if it was.
    fn expired(&self) -> Option<&'static str> {
        self.0.lock().unwrap().expired
    }
}

/// Expires `h` with `reason` once `limit` has passed. Dropping the returned
/// sender first ends the watchdog, which the worker does once netdoc is reaped.
fn watchdog(h: Handle, limit: Duration, reason: &'static str) -> Sender<()> {
    let (done, wait) = channel::<()>();
    std::thread::spawn(move || {
        if let Err(RecvTimeoutError::Timeout) = wait.recv_timeout(limit) {
            h.expire(reason);
        }
    });
    done
}

/// Keeps only the end of a pipe's output: a long watch can't grow it without
/// limit, and the last lines are the useful ones.
fn keep_tail(mut pipe: impl Read + Send + 'static) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut kept: Vec<u8> = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok(n) = pipe.read(&mut buf) {
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
    })
}

/// How long readers get to deliver what netdoc printed, once netdoc has exited.
const READ_GRACE: Duration = Duration::from_secs(1);

/// How often the supervisor looks at netdoc and at its readers.
const POLL: Duration = Duration::from_millis(20);

/// Runs a started netdoc to its end, with every wait bounded, and passes each
/// stdout line to `on_line` as it arrives. Returns the exit code and the end of
/// stderr.
///
/// Output is read on threads of their own, so a pipe that stays open, held by a
/// descendant or by netdoc itself, cannot hold the window: once netdoc has
/// exited, its readers get READ_GRACE and are then left behind.
fn supervise(
    h: &Handle,
    mut child: Child,
    mut on_line: impl FnMut(String),
) -> (Option<i32>, String) {
    let stdout = child.stdout.take().unwrap();
    let stderr = keep_tail(child.stderr.take().unwrap());
    let queue: Arc<Mutex<VecDeque<String>>> = Arc::default();
    let reader_queue = Arc::clone(&queue);
    let out = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            // Once the supervisor has gone it is the only other owner left, and
            // nothing reads what is pushed: stop reading.
            if Arc::strong_count(&reader_queue) == 1 {
                break;
            }
            reader_queue.lock().unwrap().push_back(line);
        }
    });
    h.attach(child);
    let mut out_ended: Option<Instant> = None;
    let mut stop_seen: Option<Instant> = None;
    let code = loop {
        flush(&queue, &mut on_line);
        {
            let mut s = h.0.lock().unwrap();
            match s.child.as_mut().map(Child::try_wait) {
                Some(Ok(Some(status))) => {
                    s.child = None;
                    break status.code();
                }
                Some(Ok(None)) => {}
                Some(Err(_)) | None => {
                    s.child = None;
                    break None;
                }
            }
            if out.is_finished() {
                let since = *out_ended.get_or_insert_with(Instant::now);
                if since.elapsed() > EXIT_GRACE {
                    expire_locked(&mut s, CLOSED_OUTPUT);
                }
            }
            if s.stopped {
                let since = *stop_seen.get_or_insert_with(Instant::now);
                if since.elapsed() > STOP_GRACE
                    && let Some(c) = s.child.as_mut()
                {
                    let _ = c.kill();
                }
            }
        }
        std::thread::sleep(POLL);
    };
    // netdoc has exited. Its readers get READ_GRACE to finish what it printed.
    let deadline = Instant::now() + READ_GRACE;
    while !(out.is_finished() && stderr.is_finished()) && Instant::now() < deadline {
        flush(&queue, &mut on_line);
        std::thread::sleep(POLL);
    }
    flush(&queue, &mut on_line);
    let tail = if stderr.is_finished() {
        stderr.join().unwrap_or_default()
    } else {
        String::new()
    };
    (code, tail)
}

/// Passes on the lines the reader has queued so far.
fn flush(queue: &Mutex<VecDeque<String>>, on_line: &mut impl FnMut(String)) {
    let lines: Vec<String> = queue.lock().unwrap().drain(..).collect();
    for line in lines {
        on_line(line);
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
    start_run(RUN_LIMIT, bin, profile, target, watch, tx, wake)
}

fn start_run(
    limit: Duration,
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
        let _limit = watch
            .is_none()
            .then(|| watchdog(h.clone(), limit, TOO_LONG));
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
        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.send(Msg::Failed(format!("Couldn't start netdoc: {e}")));
                // Every run ends with Finished, so the window is never left waiting.
                let _ = tx.send(Msg::Finished {
                    code: None,
                    stderr: String::new(),
                });
                wake();
                return;
            }
        };
        let mut reported = false;
        let mut failed = false;
        let mut body = String::new();
        let (code, stderr) = supervise(&h, child, |line| {
            if watch.is_none() {
                body.push_str(&line);
                body.push('\n');
            } else if !failed && !line.trim().is_empty() {
                match report::parse(&line) {
                    Ok(r) => {
                        reported = true;
                        let _ = tx.send(Msg::Report(r));
                        wake();
                    }
                    // A line cut short by a stop the user asked for is not a bad report.
                    Err(_) if h.stopped() => {}
                    Err(e) => {
                        // Stop netdoc for real, so "stopped" on screen is true.
                        failed = true;
                        h.stop();
                        let _ = tx.send(Msg::Failed(e));
                        wake();
                    }
                }
            }
        });
        // The whole body is parsed even when netdoc was expired: a complete report stands.
        if watch.is_none() && !body.trim().is_empty() {
            match report::parse(&body) {
                Ok(r) => {
                    reported = true;
                    let _ = tx.send(Msg::Report(r));
                    wake();
                }
                // A body cut short by a stop the user asked for is not a bad report.
                Err(_) if h.stopped() => {}
                Err(e) => {
                    let _ = tx.send(Msg::Failed(e));
                    wake();
                }
            }
        }
        // An expiry after a report is quiet: the report stands. Without one, say why.
        if !reported && let Some(reason) = h.expired() {
            let _ = tx.send(Msg::Failed(reason.into()));
            wake();
        }
        let _ = tx.send(Msg::Finished { code, stderr });
        wake();
    });
    handle
}

/// `netdoc --support FILE [target]`: the privacy-conscious report for sharing.
/// `stop` ends it early. The caller joins the returned thread, which is when
/// the claimed file has been cleaned up.
pub fn save_support(
    stop: Handle,
    bin: PathBuf,
    profile: Option<String>,
    target: Option<String>,
    dest: PathBuf,
    tx: Sender<Msg>,
    wake: impl Fn() + Send + 'static,
) -> std::thread::JoinHandle<()> {
    start_save(RUN_LIMIT, stop, bin, (profile, target), dest, tx, wake)
}

fn start_save(
    limit: Duration,
    stop: Handle,
    bin: PathBuf,
    (profile, target): (Option<String>, Option<String>),
    dest: PathBuf,
    tx: Sender<Msg>,
    wake: impl Fn() + Send + 'static,
) -> std::thread::JoinHandle<()> {
    let h = stop;
    std::thread::spawn(move || {
        let _limit = watchdog(h.clone(), limit, TOO_LONG);
        // The name is claimed before netdoc runs, so no other export can take
        // it. netdoc's own write replaces the empty claim; a failed or stopped
        // export removes it, so nothing that looks like a report is left behind.
        let res = match reserve(dest) {
            Err(e) => Err(format!("Couldn't create the report file: {e}")),
            Ok(dest) => {
                let mut cmd = netdoc_command(&bin);
                cmd.arg("--support").arg(&dest);
                if let Some(p) = &profile {
                    cmd.arg("--profile").arg(p);
                }
                if let Some(t) = &target {
                    // "--" so a target can never be read as an option.
                    cmd.arg("--").arg(t);
                }
                cmd.stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                match cmd.spawn() {
                    Err(e) => {
                        let _ = std::fs::remove_file(&dest);
                        Err(format!("Couldn't start netdoc: {e}"))
                    }
                    Ok(child) => {
                        let (code, stderr) = supervise(&h, child, |_| {});
                        // 0 = healthy, 1 = a problem was found; both write the file.
                        // Anything else (2 = usage or write error, or a stop) means it didn't.
                        let written = matches!(code, Some(0 | 1))
                            && std::fs::metadata(&dest).is_ok_and(|m| m.len() > 0);
                        if written {
                            Ok(dest)
                        } else {
                            let _ = std::fs::remove_file(&dest);
                            Err(if let Some(reason) = h.expired() {
                                reason.into()
                            } else if h.stopped() {
                                "The report was stopped before it was written.".into()
                            } else {
                                format!("netdoc didn't write the report: {}", stderr.trim())
                            })
                        }
                    }
                }
            }
        };
        let _ = tx.send(Msg::Saved(res));
        wake();
    })
}

/// How many names to try in one folder before giving up.
const NAME_TRIES: u32 = 1000;

/// Claims the first free `name.ndoc`, `name-2.ndoc`, `name-3.ndoc`… by
/// creating it empty. Creating is the claim: the check and the reservation are
/// one operation, so exports in other processes can't pick the same name.
fn reserve(dest: PathBuf) -> std::io::Result<PathBuf> {
    let stem = dest
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    for n in 1..=NAME_TRIES {
        let path = if n == 1 {
            dest.clone()
        } else {
            dest.with_file_name(format!("{stem}-{n}.ndoc"))
        };
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            // The handle closes here, before netdoc writes to the path (Windows
            // can't rename over a file that is still open).
            Ok(_) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "no free file name for the report",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::{Receiver, channel};
    use std::time::{Duration, Instant};

    /// The kinds of message up to and including `Finished`, or None if it
    /// doesn't arrive within `limit`.
    fn until_finished(rx: &Receiver<Msg>, limit: Duration) -> Option<Vec<&'static str>> {
        let deadline = Instant::now() + limit;
        let mut seen = Vec::new();
        loop {
            let left = deadline.checked_duration_since(Instant::now())?;
            match rx.recv_timeout(left).ok()? {
                Msg::Report(_) => seen.push("report"),
                Msg::Failed(_) => seen.push("failed"),
                Msg::Saved(_) => seen.push("saved"),
                Msg::Finished { .. } => {
                    seen.push("finished");
                    return Some(seen);
                }
            }
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("netdoc-gui-{name}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A stand-in netdoc: a shell script running `body`.
    #[cfg(unix)]
    fn fake_netdoc(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("netdoc-fake");
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn a_missing_netdoc_still_finishes() {
        let (tx, rx) = channel();
        let _h = run(
            PathBuf::from("/nonexistent/netdoc"),
            None,
            None,
            None,
            tx,
            || {},
        );
        assert_eq!(
            until_finished(&rx, Duration::from_secs(10)),
            Some(vec!["failed", "finished"])
        );
    }

    #[cfg(unix)]
    #[test]
    fn stop_reaches_a_netdoc_that_is_still_starting() {
        let dir = scratch("early-stop");
        let (tx, rx) = channel();
        let h = run(
            fake_netdoc(&dir, "exec sleep 60"),
            None,
            None,
            None,
            tx,
            || {},
        );
        h.stop();
        let seen = until_finished(&rx, Duration::from_secs(20));
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            seen.is_some(),
            "a stop before the child was attached was lost"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_stop_after_a_report_is_quiet() {
        let dir = scratch("late-stop");
        let (tx, rx) = channel();
        let h = run(
            fake_netdoc(
                &dir,
                "echo '{\"version\":\"x\",\"target\":null,\"checks\":[],\"summary\":\"x\",\"verdict\":\"ok\",\"ok\":true}'\nexec sleep 60",
            ),
            None,
            None,
            Some(5),
            tx,
            || {},
        );
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(10)),
            Ok(Msg::Report(_))
        ));
        h.stop();
        let rest = until_finished(&rx, Duration::from_secs(20));
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            rest,
            Some(vec!["finished"]),
            "a stop must not report a failure"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_stopped_export_removes_its_claim_promptly() {
        let dir = scratch("stopped-export");
        let dest = dir.join("network-doctor-report.ndoc");
        let (tx, _rx) = channel();
        let stop = Handle::default();
        let join = save_support(
            stop.clone(),
            fake_netdoc(&dir, "exec sleep 60"),
            None,
            None,
            dest.clone(),
            tx,
            || {},
        );
        std::thread::sleep(Duration::from_millis(200));
        stop.stop();
        let (done_tx, done_rx) = channel();
        std::thread::spawn(move || {
            let _ = join.join();
            let _ = done_tx.send(());
        });
        let finished = done_rx.recv_timeout(Duration::from_secs(20)).is_ok();
        let left = dest.exists();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(finished, "the export worker didn't finish after a stop");
        assert!(!left, "a stopped export left its claimed file behind");
    }

    /// netdoc prints its report, closes its output, and then never exits. The
    /// window must not wait on it indefinitely.
    #[cfg(unix)]
    #[test]
    fn output_closed_without_exit_still_finishes() {
        let dir = scratch("closed-output");
        let (tx, rx) = channel();
        let body = "echo '{\"version\":\"x\",\"target\":null,\"checks\":[],\"summary\":\"x\",\"verdict\":\"ok\",\"ok\":true}'\n\
                    exec >&- 2>&-\nexec sleep 60";
        let _h = run(fake_netdoc(&dir, body), None, None, None, tx, || {});
        let seen = until_finished(&rx, Duration::from_secs(20));
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(seen, Some(vec!["report", "finished"]));
    }

    /// Negative control: a netdoc that prints its report and exits must not
    /// wait out the exit grace.
    #[cfg(unix)]
    #[test]
    fn a_normal_exit_is_not_delayed_by_the_grace() {
        let dir = scratch("normal-exit");
        let (tx, rx) = channel();
        let started = Instant::now();
        let body = "echo '{\"version\":\"x\",\"target\":null,\"checks\":[],\"summary\":\"x\",\"verdict\":\"ok\",\"ok\":true}'";
        let _h = run(fake_netdoc(&dir, body), None, None, None, tx, || {});
        let seen = until_finished(&rx, Duration::from_secs(20));
        let took = started.elapsed();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(seen, Some(vec!["report", "finished"]));
        assert!(took < Duration::from_secs(2), "a normal exit took {took:?}");
    }

    /// Kills a descendant a test left running, using the pid it wrote to `pid`.
    #[cfg(unix)]
    fn kill_recorded_pid(dir: &Path) {
        if let Ok(pid) = std::fs::read_to_string(dir.join("pid")) {
            let _ = std::process::Command::new("kill")
                .args(["-KILL", pid.trim()])
                .status();
        }
    }

    /// Output held open by a descendant must not hold the window on "Checking…".
    #[cfg(unix)]
    #[test]
    fn output_held_by_a_descendant_does_not_hold_the_window() {
        let dir = scratch("held-output");
        let body = format!(
            "echo '{{\"version\":\"x\",\"target\":null,\"checks\":[],\"summary\":\"x\",\"verdict\":\"ok\",\"ok\":true}}'\n\
             sleep 600 &\necho $! > {}\nexit 0",
            dir.join("pid").display()
        );
        let (tx, rx) = channel();
        let started = Instant::now();
        let _h = run(fake_netdoc(&dir, &body), None, None, None, tx, || {});
        let seen = until_finished(&rx, Duration::from_secs(15));
        let took = started.elapsed();
        kill_recorded_pid(&dir);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(seen, Some(vec!["report", "finished"]));
        assert!(took < Duration::from_secs(8), "the window waited {took:?}");
    }

    /// netdoc that ignores SIGTERM and keeps its output open must still be
    /// stopped: Finished arrives after the stop grace.
    #[cfg(unix)]
    #[test]
    fn stop_reaches_a_netdoc_that_ignores_sigterm() {
        let dir = scratch("ignores-term");
        let body = format!(
            "trap '' TERM\necho $$ > {}\nexec sleep 600",
            dir.join("pid").display()
        );
        let (tx, rx) = channel();
        let h = run(fake_netdoc(&dir, &body), None, None, None, tx, || {});
        std::thread::sleep(Duration::from_millis(500));
        h.stop();
        let seen = until_finished(&rx, Duration::from_secs(20));
        kill_recorded_pid(&dir);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(seen, Some(vec!["finished"]));
    }

    /// Negative control: a netdoc that honours SIGTERM ends at once. The stop
    /// grace must not delay it.
    #[cfg(unix)]
    #[test]
    fn a_stop_is_quick_when_netdoc_honours_sigterm() {
        let dir = scratch("honours-term");
        let (tx, rx) = channel();
        let h = run(
            fake_netdoc(&dir, "exec sleep 600"),
            None,
            None,
            None,
            tx,
            || {},
        );
        std::thread::sleep(Duration::from_millis(500));
        let stopped_at = Instant::now();
        h.stop();
        let seen = until_finished(&rx, Duration::from_secs(20));
        let took = stopped_at.elapsed();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(seen, Some(vec!["finished"]));
        assert!(took < Duration::from_secs(2), "a stop took {took:?}");
    }

    /// An export whose stderr a descendant holds open must still release its
    /// reserved name: the failed export removes its claim.
    #[cfg(unix)]
    #[test]
    fn an_export_held_open_by_a_descendant_releases_its_claim() {
        let dir = scratch("held-export");
        let dest = dir.join("network-doctor-report.ndoc");
        let body = format!(
            "sleep 600 >&2 &\necho $! > {}\nexit 1",
            dir.join("pid").display()
        );
        let (tx, rx) = channel();
        let _join = save_support(
            Handle::default(),
            fake_netdoc(&dir, &body),
            None,
            None,
            dest.clone(),
            tx,
            || {},
        );
        // Clean up before asserting, so a failed assertion leaves nothing running.
        let res = match rx.recv_timeout(Duration::from_secs(15)) {
            Ok(Msg::Saved(r)) => Some(r),
            _ => None,
        };
        let left = dest.exists();
        kill_recorded_pid(&dir);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(res.is_some(), "the export never reported back");
        assert!(res.unwrap().is_err());
        assert!(!left, "a failed export left its claimed file behind");
    }

    /// A check that never finishes is expired, so the window can't wait forever.
    #[cfg(unix)]
    #[test]
    fn a_check_that_never_finishes_is_expired() {
        let dir = scratch("never-finishes");
        let (tx, rx) = channel();
        let _h = start_run(
            Duration::from_secs(1),
            fake_netdoc(&dir, "exec sleep 60"),
            None,
            None,
            None,
            tx,
            || {},
        );
        let seen = until_finished(&rx, Duration::from_secs(20));
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(seen, Some(vec!["failed", "finished"]));
    }

    /// An export that never finishes is expired, and its claimed name is released.
    #[cfg(unix)]
    #[test]
    fn a_stalled_export_is_expired_and_leaves_no_claim() {
        let dir = scratch("stalled-export");
        let dest = dir.join("network-doctor-report.ndoc");
        let (tx, rx) = channel();
        let _join = start_save(
            Duration::from_secs(1),
            Handle::default(),
            fake_netdoc(&dir, "exec sleep 60"),
            (None, None),
            dest.clone(),
            tx,
            || {},
        );
        let res = match rx.recv_timeout(Duration::from_secs(20)) {
            Ok(Msg::Saved(r)) => r,
            _ => panic!("the stalled export never finished"),
        };
        let left = dest.exists();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(res.is_err(), "a stalled export reported success");
        assert!(!left, "a stalled export left its claimed file behind");
    }

    #[cfg(unix)]
    #[test]
    fn a_bad_watch_line_stops_netdoc_and_says_so() {
        let dir = scratch("bad-line");
        let (tx, rx) = channel();
        let _h = run(
            fake_netdoc(&dir, "echo 'not json'\nexec sleep 60"),
            None,
            None,
            Some(5),
            tx,
            || {},
        );
        let seen = until_finished(&rx, Duration::from_secs(20));
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(seen, Some(vec!["failed", "finished"]));
    }

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
        assert_eq!(reserve(a.clone()).unwrap(), a);
        assert_eq!(std::fs::read_to_string(&a).unwrap(), "");
        assert_eq!(reserve(a.clone()).unwrap(), dir.join("r-2.ndoc"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Exports from separate processes must never share a name. Each child
    /// picks a name, then waits until every peer has picked one, so a
    /// check-then-write choice gives all of them the same path.
    #[test]
    fn concurrent_exports_never_share_a_name() {
        const PEERS: usize = 8;
        if let Ok(dir) = std::env::var("NETDOC_GUI_CLAIM_DIR") {
            let dir = PathBuf::from(dir);
            let me: usize = std::env::var("NETDOC_GUI_CLAIM_ID")
                .unwrap()
                .parse()
                .unwrap();
            let name = reserve(dir.join("network-doctor-report.ndoc")).unwrap();
            std::fs::write(dir.join(format!("ready-{me}")), "").unwrap();
            while std::fs::read_dir(&dir)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| e.file_name().to_string_lossy().starts_with("ready-"))
                .count()
                < PEERS
            {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            println!("CLAIM {}", name.display());
            return;
        }
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("netdoc-gui-claim-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = std::env::current_exe().unwrap();
        let children: Vec<_> = (0..PEERS)
            .map(|i| {
                std::process::Command::new(&exe)
                    .args([
                        "--exact",
                        "runner::tests::concurrent_exports_never_share_a_name",
                        "--nocapture",
                    ])
                    .env("NETDOC_GUI_CLAIM_DIR", &dir)
                    .env("NETDOC_GUI_CLAIM_ID", i.to_string())
                    .stdout(Stdio::piped())
                    .spawn()
                    .unwrap()
            })
            .collect();
        let mut names = std::collections::BTreeSet::new();
        for child in children {
            let out = child.wait_with_output().unwrap();
            assert!(
                out.status.success(),
                "child failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                if let Some(p) = line.strip_prefix("CLAIM ") {
                    names.insert(p.to_string());
                }
            }
        }
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(names.len(), PEERS, "exports shared a name: {names:?}");
    }
}
