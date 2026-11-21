//! Finds and runs the `netdoc` program.

use crate::report::{self, Outcome};
use std::collections::VecDeque;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How much of netdoc's error output to keep.
const STDERR_KEEP: usize = 8 * 1024;

/// The most one report may be: one line of a watch, or all a one-shot check prints.
const MAX_REPORT: usize = 4 * 1024 * 1024;

/// The most output that may wait for the window to take it.
const MAX_QUEUED: usize = 2 * MAX_REPORT;

/// The most `netdoc --version` may print.
const MAX_VERSION: usize = 4 * 1024;

const TOO_MUCH: &str = "netdoc printed more than this app accepts, so it was stopped.";

const UNREADABLE: &str = "netdoc's output couldn't be read, so it was stopped.";

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
    // Only Unix and Windows change the command below.
    #[cfg_attr(not(any(unix, windows)), allow(unused_mut))]
    let mut cmd = Command::new(bin);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Its own process group, so a SIGKILL to the group reaches its descendants.
        cmd.process_group(0);
    }
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

/// How long netdoc may take to print its version.
const VERSION_LIMIT: Duration = Duration::from_secs(5);

/// Asks netdoc for its version on a thread of its own, bounded like any other
/// run, so the window starts without waiting for it. The answer is `None` if
/// netdoc printed nothing in time, or more than a version. `wake` is called
/// once the answer is sent, so the window redraws with it.
pub fn start_version(bin: PathBuf, wake: impl Fn() + Send + 'static) -> Receiver<Option<String>> {
    start_version_limited(VERSION_LIMIT, bin, wake)
}

fn start_version_limited(
    limit: Duration,
    bin: PathBuf,
    wake: impl Fn() + Send + 'static,
) -> Receiver<Option<String>> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let h = Handle::default();
        let _limit = watchdog(h.clone(), limit, "netdoc didn't print its version in time.");
        let mut cmd = netdoc_command(&bin);
        cmd.arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let version = match cmd.spawn() {
            Ok(child) => {
                let mut text = String::new();
                let mut over = false;
                supervise(&h, child, |line| {
                    if over {
                        return;
                    }
                    if text.len() + line.len() + 1 > MAX_VERSION {
                        over = true;
                        h.expire(TOO_MUCH);
                        return;
                    }
                    text.push_str(&line);
                    text.push('\n');
                });
                (!over)
                    .then(|| text.trim().to_string())
                    .filter(|v| !v.is_empty())
            }
            Err(_) => None,
        };
        let _ = tx.send(version);
        wake();
    });
    rx
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

/// SIGKILL to netdoc's whole process group on Unix, so the descendants it left
/// behind go too. Elsewhere only the child itself can be killed, by the caller.
#[cfg(unix)]
fn kill_tree(pid: u32) {
    // SAFETY: a negative pid addresses the process group led by netdoc. If the
    // group has gone, the call fails harmlessly.
    unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL) };
}

#[cfg(not(unix))]
fn kill_tree(_pid: u32) {}

/// Whether netdoc has exited. On Unix this looks without reaping it, so its
/// process id, and the group id with it, stay reserved until `try_wait`.
#[cfg(unix)]
fn has_exited(child: &mut Child) -> std::io::Result<bool> {
    // SAFETY: `info` is plain data that waitid fills in, and the child is not
    // yet reaped, so its id is still its own. WNOWAIT leaves it waitable.
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let flags = libc::WEXITED | libc::WNOHANG | libc::WNOWAIT;
        if libc::waitid(libc::P_PID, child.id() as libc::id_t, &mut info, flags) != 0 {
            let e = std::io::Error::last_os_error();
            return if e.kind() == std::io::ErrorKind::Interrupted {
                Ok(false)
            } else {
                Err(e)
            };
        }
        // With WNOHANG a child that is still running leaves si_pid at zero.
        Ok(info.si_pid() != 0)
    }
}

/// Elsewhere there is no process group to protect, so this reaps.
#[cfg(not(unix))]
fn has_exited(child: &mut Child) -> std::io::Result<bool> {
    child.try_wait().map(|status| status.is_some())
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

    /// Stops netdoc for `reason`, unless the user already stopped it.
    fn expire(&self, reason: &'static str) {
        expire_locked(&mut self.0.lock().unwrap(), reason);
    }

    /// Hands the started child over. A stop asked for before this applies now.
    fn attach(&self, mut child: Child) {
        let mut s = self.0.lock().unwrap();
        if s.stopped {
            ask_to_stop(&mut child);
        }
        s.child = Some(child);
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
            expire_locked(&mut h.0.lock().unwrap(), reason);
        }
    });
    done
}

/// Keeps only the end of a pipe's output: a long watch can't grow it without
/// limit, and the last lines are the useful ones. The text is cleaned here,
/// because it is shown to the user.
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
        report::clean_lines(&String::from_utf8_lossy(&kept))
    })
}

/// How long readers get to deliver what netdoc printed, once netdoc has exited.
const READ_GRACE: Duration = Duration::from_secs(1);

/// How often the supervisor looks at netdoc and at its readers.
const POLL: Duration = Duration::from_millis(20);

/// Lines read from netdoc that the supervisor has not taken yet.
#[derive(Default)]
struct Lines {
    queued: VecDeque<String>,
    /// The size of `queued`, in bytes.
    bytes: usize,
    /// Why reading stopped early, until the supervisor takes it.
    failed: Option<&'static str>,
}

/// Reads `pipe` to its end in fixed-size chunks and queues each line. A line
/// longer than `line_cap`, or more than `queue_cap` waiting to be taken, ends
/// the reading with TOO_MUCH. A read error or text that isn't UTF-8 ends it
/// with UNREADABLE. Neither is mistaken for the end of the output.
fn read_lines(
    mut pipe: impl Read,
    lines: &Arc<Mutex<Lines>>,
    line_cap: usize,
    queue_cap: usize,
) -> Result<(), &'static str> {
    let mut line: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = match pipe.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(UNREADABLE),
        };
        let mut rest = &buf[..n];
        while let Some(end) = rest.iter().position(|b| *b == b'\n') {
            line.extend_from_slice(&rest[..end]);
            rest = &rest[end + 1..];
            if line.len() > line_cap {
                return Err(TOO_MUCH);
            }
            if !queue_line(lines, std::mem::take(&mut line), queue_cap)? {
                return Ok(());
            }
        }
        line.extend_from_slice(rest);
        if line.len() > line_cap {
            return Err(TOO_MUCH);
        }
    }
    if !line.is_empty() {
        queue_line(lines, line, queue_cap)?;
    }
    Ok(())
}

/// Queues one line. False once the supervisor has gone: it is then the only
/// other owner left, nothing reads what is queued, and reading can stop.
fn queue_line(
    lines: &Arc<Mutex<Lines>>,
    mut line: Vec<u8>,
    queue_cap: usize,
) -> Result<bool, &'static str> {
    if Arc::strong_count(lines) == 1 {
        return Ok(false);
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    let line = String::from_utf8(line).map_err(|_| UNREADABLE)?;
    let mut l = lines.lock().unwrap();
    if l.bytes + line.len() > queue_cap {
        return Err(TOO_MUCH);
    }
    l.bytes += line.len();
    l.queued.push_back(line);
    Ok(true)
}

/// Runs a started netdoc to its end, with every wait bounded, and passes each
/// stdout line to `on_line` as it arrives. Returns the exit code and the end of
/// stderr. A child started without a stdout or stderr pipe has nothing read
/// from that stream.
///
/// Output is read on threads of their own, so a pipe that stays open, held by a
/// descendant or by netdoc itself, cannot hold the window: once netdoc has
/// exited, its readers get READ_GRACE and are then left behind. Output that
/// can't be read, or is too large, expires the run with the reason.
fn supervise(
    h: &Handle,
    mut child: Child,
    mut on_line: impl FnMut(String),
) -> (Option<i32>, String) {
    let lines: Arc<Mutex<Lines>> = Arc::default();
    let out = child.stdout.take().map(|pipe| {
        let lines = Arc::clone(&lines);
        std::thread::spawn(move || {
            if let Err(reason) = read_lines(pipe, &lines, MAX_REPORT, MAX_QUEUED) {
                lines.lock().unwrap().failed = Some(reason);
            }
        })
    });
    let stderr = child.stderr.take().map(keep_tail);
    let pid = child.id();
    h.attach(child);
    let mut out_ended: Option<Instant> = None;
    let mut stop_seen: Option<Instant> = None;
    let code = loop {
        flush(&lines, &mut on_line);
        {
            let mut s = h.0.lock().unwrap();
            if let Some(reason) = lines.lock().unwrap().failed.take() {
                expire_locked(&mut s, reason);
            }
            match s.child.as_mut().map(has_exited) {
                Some(Ok(true)) => {
                    // netdoc has exited but is not reaped yet, so its group id
                    // cannot have been reused: kill what it left behind first
                    // (a descendant may still hold a pipe open), then reap it.
                    kill_tree(pid);
                    let status = s.child.take().and_then(|mut c| c.try_wait().ok().flatten());
                    break status.and_then(|st| st.code());
                }
                Some(Ok(false)) => {}
                Some(Err(_)) | None => {
                    s.child = None;
                    break None;
                }
            }
            if out.as_ref().is_some_and(|t| t.is_finished()) {
                let since = *out_ended.get_or_insert_with(Instant::now);
                if since.elapsed() > EXIT_GRACE {
                    expire_locked(&mut s, CLOSED_OUTPUT);
                }
            }
            if s.stopped {
                let since = *stop_seen.get_or_insert_with(Instant::now);
                if since.elapsed() > STOP_GRACE {
                    kill_tree(pid);
                    if let Some(c) = s.child.as_mut() {
                        let _ = c.kill();
                    }
                }
            }
        }
        std::thread::sleep(POLL);
    };
    // netdoc has exited. Its readers get READ_GRACE to finish what it printed.
    let done = |t: &Option<std::thread::JoinHandle<()>>| t.as_ref().is_none_or(|t| t.is_finished());
    let deadline = Instant::now() + READ_GRACE;
    while !(done(&out) && stderr.as_ref().is_none_or(|t| t.is_finished()))
        && Instant::now() < deadline
    {
        flush(&lines, &mut on_line);
        std::thread::sleep(POLL);
    }
    flush(&lines, &mut on_line);
    // Reading may have failed just as netdoc exited: the reason still counts.
    if let Some(reason) = lines.lock().unwrap().failed.take() {
        h.expire(reason);
    }
    let tail = match stderr {
        Some(t) if t.is_finished() => t.join().unwrap_or_default(),
        _ => String::new(),
    };
    (code, tail)
}

/// Passes on the lines the reader has queued so far.
fn flush(lines: &Mutex<Lines>, on_line: &mut impl FnMut(String)) {
    let taken: Vec<String> = {
        let mut l = lines.lock().unwrap();
        l.bytes = 0;
        l.queued.drain(..).collect()
    };
    for line in taken {
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
        let mut over = false;
        let (code, stderr) = supervise(&h, child, |line| {
            if watch.is_none() {
                if over {
                    return;
                }
                if body.len() + line.len() + 1 > MAX_REPORT {
                    over = true;
                    body.clear();
                    h.expire(TOO_MUCH);
                    return;
                }
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
        if watch.is_none() && !over && !body.trim().is_empty() {
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
        // A one-shot check that produced its report stands, so an expiry after
        // it is quiet. A watch was meant to go on, so its expiry is always said:
        // the window shows it beside the last report.
        if (!reported || watch.is_some())
            && let Some(reason) = h.expired()
        {
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
                // Nothing reads what an export prints, so it is not collected.
                cmd.stdin(Stdio::null())
                    .stdout(Stdio::null())
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
    //! Lifecycle tests. Those marked `cfg(unix)` run fake netdoc shell scripts,
    //! so they run on Unix only, and the Linux-only ones also read /proc.
    //! Windows does not exercise the stop, expiry, descendant or stalled-version
    //! paths: they need Unix signals and process groups. On Windows, only the
    //! child itself can be killed, so a descendant that outlives netdoc is not
    //! cleaned up. Those paths are checked there by reading the code only.
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

    /// A fresh directory for one test. Only the Unix-only lifecycle tests use it.
    #[cfg(unix)]
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

    /// Netdoc's error text is shown to the user, so escape sequences, other
    /// control characters and bidi overrides are removed when it is read. Line
    /// breaks stay. ponytail: the ESC goes but its "[31m" parameters stay
    /// visible; stripping whole CSI sequences would also change report text.
    #[test]
    fn netdoc_error_text_is_cleaned_and_keeps_its_lines() {
        let raw: &'static [u8] = b"\x1b[31mboom\x07\xe2\x80\xae txt\nsecond line\n";
        let text = keep_tail(raw).join().unwrap();
        assert!(!text.contains('\u{1b}'), "escape left in {text:?}");
        assert!(!text.contains('\u{7}'), "bell left in {text:?}");
        assert!(!text.contains('\u{202e}'), "bidi override left in {text:?}");
        assert!(
            text.contains("boom") && text.contains("txt"),
            "text lost: {text:?}"
        );
        assert!(
            text.contains("txt\nsecond line"),
            "line break lost: {text:?}"
        );
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

    /// Waits, for a bounded time, until a fake netdoc has written its pid file.
    #[cfg(unix)]
    fn wait_for_pid_file(dir: &Path) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if std::fs::read_to_string(dir.join("pid")).is_ok_and(|p| !p.trim().is_empty()) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
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
        // The fixture writes its pid after it has started ignoring SIGTERM.
        let ready = wait_for_pid_file(&dir);
        h.stop();
        let seen = until_finished(&rx, Duration::from_secs(20));
        kill_recorded_pid(&dir);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(ready, "the fake netdoc never wrote its pid file");
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

    /// Whether a process is still running. A zombie has exited, so it doesn't count.
    #[cfg(target_os = "linux")]
    fn process_alive(pid: &str) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
            stat.rsplit(')')
                .next()
                .is_some_and(|rest| !rest.trim_start().starts_with('Z'))
        })
    }

    /// A descendant that netdoc leaves behind must not outlive it. Linux only:
    /// the check reads /proc.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_descendant_left_behind_is_killed() {
        let dir = scratch("descendant");
        let body = format!(
            "sleep 600 &\necho $! > {}\necho '{{\"version\":\"x\",\"target\":null,\"checks\":[],\"summary\":\"x\",\"verdict\":\"ok\",\"ok\":true}}'\nexit 0",
            dir.join("pid").display()
        );
        let (tx, rx) = channel();
        let _h = run(fake_netdoc(&dir, &body), None, None, None, tx, || {});
        let seen = until_finished(&rx, Duration::from_secs(15));
        let pid = std::fs::read_to_string(dir.join("pid")).unwrap_or_default();
        let deadline = Instant::now() + Duration::from_secs(5);
        while process_alive(pid.trim()) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let alive = process_alive(pid.trim());
        kill_recorded_pid(&dir);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(seen, Some(vec!["report", "finished"]));
        assert!(!alive, "a descendant outlived netdoc");
    }

    /// A netdoc that stalls on `--version` must not hold the caller: the
    /// answer comes back as `None` once the limit and the stop grace have passed.
    #[cfg(unix)]
    #[test]
    fn a_stalled_version_check_does_not_block_its_caller() {
        let dir = scratch("stalled-version");
        let body = format!(
            "trap '' TERM\necho $$ > {}\nexec sleep 600",
            dir.join("pid").display()
        );
        let started = Instant::now();
        let rx = start_version_limited(Duration::from_secs(1), fake_netdoc(&dir, &body), || {});
        let caller_waited = started.elapsed();
        let answer = rx.recv_timeout(Duration::from_secs(20));
        kill_recorded_pid(&dir);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            caller_waited < Duration::from_millis(500),
            "the caller waited {caller_waited:?}"
        );
        assert_eq!(answer, Ok(None));
    }

    /// Negative control: a prompt netdoc's version is read.
    #[cfg(unix)]
    #[test]
    fn a_prompt_version_check_reads_the_version() {
        let dir = scratch("prompt-version");
        let (woke_tx, woke_rx) = channel();
        let rx = start_version_limited(
            Duration::from_secs(5),
            fake_netdoc(&dir, "echo 'netdoc v9.9.9'"),
            move || {
                let _ = woke_tx.send(());
            },
        );
        let answer = rx.recv_timeout(Duration::from_secs(10));
        let woke = woke_rx.recv_timeout(Duration::from_secs(10)).is_ok();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(answer, Ok(Some("netdoc v9.9.9".to_string())));
        assert!(woke, "the window was not woken for the version");
    }

    /// A version far longer than a version is refused, not kept.
    #[cfg(unix)]
    #[test]
    fn an_oversized_version_is_refused() {
        let dir = scratch("big-version");
        let body = "i=0\nwhile [ $i -lt 200 ]; do echo 0123456789012345678901234567890123456789; i=$((i+1)); done";
        let rx = start_version_limited(Duration::from_secs(5), fake_netdoc(&dir, body), || {});
        let answer = rx.recv_timeout(Duration::from_secs(20));
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(answer, Ok(None));
    }

    /// The lines `read_lines` queues from `input`, and how the reading ended.
    fn lines_of(
        input: &[u8],
        line_cap: usize,
        queue_cap: usize,
    ) -> (Vec<String>, Result<(), &'static str>) {
        let lines: Arc<Mutex<Lines>> = Arc::default();
        // A second owner, as the supervisor is: without one the reader stops.
        let _supervisor = Arc::clone(&lines);
        let end = read_lines(input, &lines, line_cap, queue_cap);
        let queued = lines.lock().unwrap().queued.drain(..).collect();
        (queued, end)
    }

    #[test]
    fn lines_up_to_the_cap_are_kept_whole() {
        // Both line endings, and a last line with none.
        let (got, end) = lines_of(b"12345678\nab\r\n\nlast", 8, 64);
        assert_eq!(got, ["12345678", "ab", "", "last"]);
        assert_eq!(end, Ok(()));
        // A line longer than one read chunk is still one line.
        let long = "x".repeat(20_000);
        let (got, end) = lines_of(format!("{long}\n").as_bytes(), 20_000, 64_000);
        assert_eq!(got, [long]);
        assert_eq!(end, Ok(()));
    }

    #[test]
    fn output_over_a_cap_is_a_failure_not_an_end() {
        // One line over the line cap, with and without its line break.
        assert_eq!(lines_of(b"123456789\n", 8, 64).1, Err(TOO_MUCH));
        assert_eq!(lines_of(b"123456789", 8, 64).1, Err(TOO_MUCH));
        // Lines that fit one by one, but not all waiting at once.
        let (got, end) = lines_of(b"1234\n1234\n1234\n", 8, 8);
        assert_eq!(got, ["1234", "1234"]);
        assert_eq!(end, Err(TOO_MUCH));
    }

    #[test]
    fn unreadable_output_is_a_failure_not_an_end() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("broken pipe"))
            }
        }
        let lines: Arc<Mutex<Lines>> = Arc::default();
        assert_eq!(read_lines(Broken, &lines, 8, 64), Err(UNREADABLE));
        let (got, end) = lines_of(b"ok\n\xff\xfe\nnever\n", 8, 64);
        assert_eq!(got, ["ok"]);
        assert_eq!(end, Err(UNREADABLE));
    }

    /// A one-shot check whose output isn't text fails with the reason. It must
    /// not read as a normal end with a cut-off report.
    #[cfg(unix)]
    #[test]
    fn unreadable_output_fails_the_check() {
        let dir = scratch("unreadable");
        let (tx, rx) = channel();
        let _h = run(
            fake_netdoc(&dir, "printf '\\377\\376\\n'\nexit 0"),
            None,
            None,
            None,
            tx,
            || {},
        );
        let mut reason = None;
        let deadline = Instant::now() + Duration::from_secs(20);
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match rx.recv_timeout(left) {
                Ok(Msg::Failed(e)) => reason = Some(e),
                Ok(Msg::Finished { .. }) | Err(_) => break,
                Ok(_) => {}
            }
        }
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(reason.as_deref(), Some(UNREADABLE));
    }

    /// A watch that has reported and then closes its output without exiting
    /// is expired, and says so: the window must not show it as still watching
    /// or as a quiet end.
    #[cfg(unix)]
    #[test]
    fn a_watch_expiry_is_said_even_after_a_report() {
        let dir = scratch("watch-expiry");
        let (tx, rx) = channel();
        let body = "echo '{\"version\":\"x\",\"target\":null,\"checks\":[],\"summary\":\"x\",\"verdict\":\"ok\",\"ok\":true}'\n\
                    exec >&- 2>&-\nexec sleep 60";
        let _h = run(fake_netdoc(&dir, body), None, None, Some(5), tx, || {});
        let seen = until_finished(&rx, Duration::from_secs(30));
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(seen, Some(vec!["report", "failed", "finished"]));
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

    /// How many child processes race for a name in `run_claims`.
    const PEERS: usize = 8;

    /// How many peers have written their ready file so far.
    fn ready_peers(dir: &Path) -> usize {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("ready-"))
            .count()
    }

    /// The check-then-write claim that export naming used before `reserve`.
    fn naive_claim(dir: &Path) -> PathBuf {
        let dest = dir.join("network-doctor-report.ndoc");
        if dest.exists() {
            dir.join("network-doctor-report-2.ndoc")
        } else {
            dest
        }
    }

    /// The first claim that another peer also holds, if any.
    fn duplicate_claim(claims: &[String]) -> Option<&String> {
        let mut seen = std::collections::HashSet::new();
        claims.iter().find(|c| !seen.insert(c.as_str()))
    }

    /// The child side of `run_claims`. As an ordinary test it does nothing: it
    /// acts only when the parent has set its environment. It claims a name,
    /// writes the claim to a file, and waits until every peer has claimed too.
    #[test]
    fn claim_child() {
        let Ok(dir) = std::env::var("NETDOC_GUI_CLAIM_DIR") else {
            return;
        };
        let dir = PathBuf::from(dir);
        let me: usize = std::env::var("NETDOC_GUI_CLAIM_ID")
            .unwrap()
            .parse()
            .unwrap();
        std::fs::write(dir.join(format!("ready-{me}")), "").unwrap();
        // Released together: the parent opens the gate once every child is ready,
        // so the claims race within microseconds of each other. Bounded.
        let deadline = Instant::now() + Duration::from_secs(30);
        while !dir.join("go").exists() {
            assert!(
                Instant::now() < deadline,
                "the parent never opened the gate"
            );
        }
        let claim = if std::env::var_os("NETDOC_GUI_CLAIM_NAIVE").is_some() {
            naive_claim(&dir)
        } else {
            reserve(dir.join("network-doctor-report.ndoc")).unwrap()
        };
        std::fs::write(dir.join(format!("claim-{me}")), claim.display().to_string()).unwrap();
    }

    /// `PEERS` child processes claim names at the same moment, and this returns
    /// each child's claim, read from the file it wrote. Results travel through
    /// files, not stdout, so they do not depend on libtest's output format or on
    /// the thread count the runner was given.
    fn run_claims(naive: bool) -> Vec<String> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("netdoc-gui-claims-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = std::env::current_exe().unwrap();
        let children: Vec<_> = (0..PEERS)
            .map(|i| {
                let mut cmd = std::process::Command::new(&exe);
                cmd.args(["--exact", "runner::tests::claim_child", "--nocapture"])
                    .env("NETDOC_GUI_CLAIM_DIR", &dir)
                    .env("NETDOC_GUI_CLAIM_ID", i.to_string())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped());
                if naive {
                    cmd.env("NETDOC_GUI_CLAIM_NAIVE", "1");
                }
                cmd.spawn().unwrap()
            })
            .collect();
        let deadline = Instant::now() + Duration::from_secs(30);
        while ready_peers(&dir) < PEERS && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        std::fs::write(dir.join("go"), "").unwrap();
        let mut failures = Vec::new();
        for child in children {
            let out = child.wait_with_output().unwrap();
            if !out.status.success() {
                failures.push(String::from_utf8_lossy(&out.stderr).into_owned());
            }
        }
        let claims: Vec<String> = (0..PEERS)
            .filter_map(|i| std::fs::read_to_string(dir.join(format!("claim-{i}"))).ok())
            .collect();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(failures.is_empty(), "a child failed: {failures:?}");
        assert_eq!(claims.len(), PEERS, "a child wrote no claim");
        claims
    }

    /// Exports from separate processes must never share a name.
    #[test]
    fn concurrent_exports_never_share_a_name() {
        let claims = run_claims(false);
        assert_eq!(
            duplicate_claim(&claims),
            None,
            "exports shared a name: {claims:?}"
        );
    }

    /// Negative control: the harness must catch the check-then-write claim.
    /// Every child sees the name free before any of them writes, so they all pick it.
    #[test]
    fn duplicate_claims_are_caught() {
        assert_eq!(duplicate_claim(&["a".to_string(), "b".to_string()]), None);
        let claims = run_claims(true);
        assert!(
            duplicate_claim(&claims).is_some(),
            "the harness missed a shared name: {claims:?}"
        );
    }
}
