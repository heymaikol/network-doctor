//! The update check: what `netdoc -update-check -json` answers, what the window
//! keeps between runs about it, when it may ask again, and how the release page
//! is opened. The contract is schema/netdoc-update-check-v1.schema.json in the
//! repository. Readers ignore keys they do not know, so this does too.

use crate::report;
use serde_json::Value;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const SCHEMA: &str = "netdoc.update-check.v1";
const RELEASES: &str = "https://github.com/heymaikol/network-doctor/releases/tag/";
/// The longest installed version the window shows.
const MAX_INSTALLED: usize = 64;

/// After an unsuccessful check, the next automatic one waits this long. It
/// matches netdoc's own cache TTL, so a launch inside it asks nothing new.
pub const RETRY_AFTER_SECS: u64 = 24 * 60 * 60;

/// What a valid answer says.
#[derive(Debug, PartialEq)]
pub enum Answer {
    /// A newer stable release than the installed one.
    Newer(Release),
    /// Nothing newer to show: the build is current, not a stable release, or the check is disabled.
    Current,
    /// No answer was obtained: offline, rate limited, or a bad response from GitHub.
    Unanswered,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Release {
    pub latest: String,
    pub url: String,
    pub installed: String,
}

/// Reads an answer. `None` means the text breaks the contract, so nothing is
/// shown and nothing is recorded.
pub fn parse(text: &str) -> Option<Answer> {
    let v: Value = serde_json::from_str(text).ok()?;
    let o = v.as_object()?;
    if o.get("schema")?.as_str()? != SCHEMA {
        return None;
    }
    let status = o.get("status")?.as_str()?;
    let installed = o.get("installed")?.as_str()?;
    o.get("cached")?.as_bool()?;
    // An optional field is a string when present. Absent means not known.
    let optional = |key: &str| -> Option<Option<&str>> {
        match o.get(key) {
            None => Some(None),
            Some(v) => v.as_str().map(Some),
        }
    };
    let latest = optional("latest")?;
    let url = optional("release_url")?;
    let checked = optional("checked_at")?;
    match status {
        "update_available" => {
            let (latest, url) = (latest?, url?);
            if checked.is_none() || !is_tag(latest) || url != format!("{RELEASES}{latest}") {
                return None;
            }
            Some(Answer::Newer(Release {
                latest: latest.to_string(),
                url: url.to_string(),
                installed: shown(installed),
            }))
        }
        "offline" | "rate_limited" | "bad_response" => Some(Answer::Unanswered),
        "up_to_date" | "unknown_version" | "disabled" => Some(Answer::Current),
        _ => None,
    }
}

/// `vX.Y.Z` with canonical numbers: the only form the schema allows for `latest`.
fn is_tag(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('v') else {
        return false;
    };
    let parts: Vec<&str> = rest.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| canonical(p))
}

fn canonical(p: &str) -> bool {
    !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && (p == "0" || !p.starts_with('0'))
}

/// The installed version as the window shows it: control and bidi characters
/// removed, and a bounded length.
fn shown(s: &str) -> String {
    report::clean_lines(s).chars().take(MAX_INSTALLED).collect()
}

/// What the window keeps between runs about update checks: one `key=value` per
/// line in its config folder. A line it does not know is ignored.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Memory {
    /// The release whose banner the user dismissed.
    pub dismissed: Option<String>,
    /// When the last unsuccessful check was answered, in seconds since the Unix epoch.
    pub failed_at: Option<u64>,
    /// Automatic checks are off, by the user's choice.
    pub off: bool,
}

/// What the user chose this session and has not saved yet. Every later change
/// applies it on top of the latest file state, so a save that does not touch it
/// cannot drop it. A save that succeeds makes it part of the file, and it clears.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Pending {
    pub off: Option<bool>,
    pub dismissed: Option<String>,
}

impl Pending {
    pub fn apply(&self, m: &mut Memory) {
        if let Some(off) = self.off {
            m.off = off;
        }
        if let Some(latest) = &self.dismissed {
            m.dismissed = Some(latest.clone());
        }
    }
}

/// Reads the memory. A missing file is the default. Any other read error is
/// returned, so a change never writes over a file it could not read.
pub fn read(path: &Path) -> io::Result<Memory> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    let mut m = Memory::default();
    for line in text.lines() {
        match line.split_once('=') {
            Some(("dismissed", v)) if is_tag(v) => m.dismissed = Some(v.to_string()),
            Some(("failed_at", v)) => m.failed_at = v.parse().ok(),
            Some(("off", "1")) => m.off = true,
            Some(("off", "0")) => m.off = false,
            // A value the format does not know is not the default: an opt-out
            // that reads as "checks on" would be silently lost.
            Some(("off", _)) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the update setting has a value this window does not recognise",
                ));
            }
            _ => {}
        }
    }
    Ok(m)
}

/// Writes the memory. An error is returned, so the caller can say the setting
/// was not kept.
pub fn save(path: &Path, m: &Memory) -> io::Result<()> {
    let mut text = String::new();
    if let Some(v) = &m.dismissed {
        text += &format!("dismissed={v}\n");
    }
    if let Some(t) = m.failed_at {
        text += &format!("failed_at={t}\n");
    }
    if m.off {
        text += "off=1\n";
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Write beside the file, then rename it into place, so a reader never sees
    // half of it. The temporary name carries this process's id, so two windows
    // never write the same temporary file.
    let tmp = path.with_file_name(format!("update.{}.tmp", std::process::id()));
    let written = std::fs::write(&tmp, text).and_then(|()| std::fs::rename(&tmp, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

/// Makes one change to the memory as the file holds it now, and writes only if
/// that changes the file. Windows and processes take turns: an exclusive lock
/// on a file of its own covers the whole read, change and write, so a change
/// never runs on a copy another change is about to replace. The lock lives on
/// its own file because the memory file itself is replaced by a rename. Returns
/// what the file holds afterwards, or the error that stopped the change.
pub fn change(path: &Path, change: impl Fn(&mut Memory)) -> io::Result<Memory> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path.with_file_name("update.lock"))?;
    // Released when `lock` is dropped, after the change is written.
    lock_within(&lock, LOCK_WAIT)?;
    apply(path, change)
}

/// How long a change waits for another window's lock before it reports that it
/// could not save. The window waits on this on its UI thread, so it stays short.
const LOCK_WAIT: Duration = Duration::from_secs(1);

/// Takes the exclusive lock, giving up after `wait`, so a stalled holder cannot
/// freeze a window. A holder that lets go in time is waited out.
fn lock_within(file: &std::fs::File, wait: Duration) -> io::Result<()> {
    let deadline = Instant::now() + wait;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "another window is still changing the update setting",
                ));
            }
            Err(std::fs::TryLockError::Error(e)) => return Err(e),
        }
    }
}

/// The read, change and write of `change`, without taking the lock.
fn apply(path: &Path, change: impl Fn(&mut Memory)) -> io::Result<Memory> {
    let before = read(path)?;
    let mut after = before.clone();
    change(&mut after);
    if after != before {
        save(path, &after)?;
    }
    Ok(after)
}

/// Negative control for the tests: the same change, without the lock.
#[cfg(test)]
fn change_without_lock(path: &Path, change: impl Fn(&mut Memory)) -> io::Result<Memory> {
    apply(path, change)
}

/// Whether the window may ask at launch. The user's setting and the environment
/// (`NETDOC_NO_UPDATE_CHECK=1`) can turn checks off. After an unsuccessful check
/// the next one waits. A failure time in the future, from a clock that went
/// back, does not hold the check.
pub fn may_check(m: &Memory, env_opt_out: bool, now: u64) -> bool {
    let held = m
        .failed_at
        .is_some_and(|t| t <= now && now - t < RETRY_AFTER_SECS);
    !m.off && !env_opt_out && !held
}

/// The release to show, if it is newer than the one the user dismissed.
/// Dismissal is per release, so a newer release shows again by itself.
pub fn to_show(answer: Answer, m: &Memory) -> Option<Release> {
    match answer {
        Answer::Newer(r) if m.dismissed.as_deref() != Some(r.latest.as_str()) => Some(r),
        _ => None,
    }
}

/// The program and its arguments that open `url` in the browser. The URL is a
/// single argument: no shell reads it.
pub fn opener(url: &str) -> (&'static str, Vec<String>) {
    if cfg!(target_os = "macos") {
        ("open", vec![url.to_string()])
    } else if cfg!(windows) {
        (
            "rundll32",
            vec!["url.dll,FileProtocolHandler".into(), url.to_string()],
        )
    } else {
        ("xdg-open", vec![url.to_string()])
    }
}

/// Starts the browser on `url`. The browser's own exit is not waited for: the
/// opener's exit is reaped on a thread of its own. False if the opener could not start.
pub fn open_page(url: &str) -> bool {
    let (program, args) = opener(url);
    let spawned = Command::new(program)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    match spawned {
        Ok(mut child) => {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            true
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AVAILABLE: &str = include_str!("../tests/fixtures/update-available.json");
    const UP_TO_DATE: &str = include_str!("../tests/fixtures/update-up-to-date.json");
    const UNKNOWN: &str = include_str!("../tests/fixtures/update-unknown-version.json");
    const DISABLED: &str = include_str!("../tests/fixtures/update-disabled.json");
    const OFFLINE: &str = include_str!("../tests/fixtures/update-offline.json");
    const LIMITED: &str = include_str!("../tests/fixtures/update-rate-limited.json");
    const BAD: &str = include_str!("../tests/fixtures/update-bad-response.json");

    /// The available fixture with `from` replaced by `to`. netdoc prints compact JSON, so the patterns are compact too.
    fn with(from: &str, to: &str) -> String {
        AVAILABLE.replace(from, to)
    }

    #[test]
    fn each_shared_fixture_reads_as_its_status() {
        assert!(matches!(parse(AVAILABLE), Some(Answer::Newer(r)) if r.latest == "v2.3.0"));
        assert_eq!(parse(UP_TO_DATE), Some(Answer::Current));
        assert_eq!(parse(UNKNOWN), Some(Answer::Current));
        assert_eq!(parse(DISABLED), Some(Answer::Current));
        assert_eq!(parse(OFFLINE), Some(Answer::Unanswered));
        assert_eq!(parse(LIMITED), Some(Answer::Unanswered));
        assert_eq!(parse(BAD), Some(Answer::Unanswered));
    }

    #[test]
    fn the_release_page_is_taken_from_the_checked_tag() {
        let Some(Answer::Newer(r)) = parse(AVAILABLE) else {
            panic!("not an answer")
        };
        assert_eq!(
            r.url,
            "https://github.com/heymaikol/network-doctor/releases/tag/v2.3.0"
        );
        assert_eq!(r.installed, "2.2.1");
    }

    #[test]
    fn unknown_keys_are_ignored_as_the_schema_asks() {
        let extended = with("\"cached\":false", "\"cached\":false,\"future\":{\"x\":1}");
        assert!(matches!(parse(&extended), Some(Answer::Newer(_))));
    }

    #[test]
    fn text_that_breaks_the_contract_is_no_answer() {
        let cases = [
            ("not json", "{".to_string()),
            ("empty", String::new()),
            ("a JSON array", "[]".to_string()),
            (
                "wrong schema",
                with("netdoc.update-check.v1", "netdoc.update-check.v2"),
            ),
            (
                "unknown status",
                with("\"status\":\"update_available\"", "\"status\":\"maybe\""),
            ),
            ("missing installed", with("\"installed\":\"2.2.1\",", "")),
            (
                "cached not a bool",
                with("\"cached\":false", "\"cached\":\"no\""),
            ),
            (
                "latest not a string",
                with("\"latest\":\"v2.3.0\"", "\"latest\":230"),
            ),
            (
                "latest without v",
                with("\"latest\":\"v2.3.0\"", "\"latest\":\"2.3.0\""),
            ),
            (
                "latest with a leading zero",
                with("\"latest\":\"v2.3.0\"", "\"latest\":\"v02.3.0\""),
            ),
            (
                "latest with a prerelease",
                with("\"latest\":\"v2.3.0\"", "\"latest\":\"v2.3.0-rc.1\""),
            ),
            (
                "release page for another tag",
                with("releases/tag/v2.3.0", "releases/tag/v9.9.9"),
            ),
            (
                "release page on another host",
                with(
                    "https://github.com/heymaikol",
                    "https://evil.example/heymaikol",
                ),
            ),
            (
                "newer without release page",
                with(
                    "\"release_url\":\"https://github.com/heymaikol/network-doctor/releases/tag/v2.3.0\",",
                    "",
                ),
            ),
            (
                "newer without checked_at",
                with("\"checked_at\":\"2026-11-21T07:54:53Z\"", "\"x\":1"),
            ),
        ];
        for (name, text) in cases {
            assert_eq!(parse(&text), None, "accepted: {name}");
        }
    }

    #[test]
    fn the_installed_version_is_bounded_and_cleaned() {
        let long = "x".repeat(200);
        let text = with(
            "\"installed\":\"2.2.1\"",
            &format!("\"installed\":\"{long}\\u202e\\u0007\""),
        );
        let Some(Answer::Newer(r)) = parse(&text) else {
            panic!("not an answer")
        };
        assert_eq!(r.installed.chars().count(), MAX_INSTALLED);
        assert!(!r.installed.contains('\u{202e}') && !r.installed.contains('\u{7}'));
    }

    #[test]
    fn a_memory_round_trips_and_ignores_lines_it_does_not_know() {
        let dir = std::env::temp_dir().join(format!("netdoc-gui-memory-{}", std::process::id()));
        let path = dir.join("update");
        let m = Memory {
            dismissed: Some("v2.3.0".into()),
            failed_at: Some(1_800_000_000),
            off: true,
        };
        save(&path, &m).unwrap();
        assert_eq!(read(&path).unwrap(), m);
        std::fs::write(
            &path,
            "dismissed=not-a-tag\nfailed_at=soon\nunknown=1\noff=0\n",
        )
        .unwrap();
        assert_eq!(read(&path).unwrap(), Memory::default());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_missing_memory_file_is_the_default() {
        let path = std::env::temp_dir().join("netdoc-gui-no-such-memory-file");
        assert_eq!(read(&path).unwrap(), Memory::default());
    }

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn checks_wait_only_after_a_failure_and_never_when_turned_off() {
        let fresh = Memory::default();
        assert!(may_check(&fresh, false, NOW));
        let failed_recently = Memory {
            failed_at: Some(NOW - 3600),
            ..Memory::default()
        };
        assert!(!may_check(&failed_recently, false, NOW));
        let failed_long_ago = Memory {
            failed_at: Some(NOW - RETRY_AFTER_SECS),
            ..Memory::default()
        };
        assert!(may_check(&failed_long_ago, false, NOW));
        let off = Memory {
            off: true,
            ..Memory::default()
        };
        assert!(!may_check(&off, false, NOW));
        assert!(
            !may_check(&fresh, true, NOW),
            "the environment opt-out was ignored"
        );
    }

    #[test]
    fn a_failure_time_from_the_future_does_not_hold_the_check() {
        let ahead = Memory {
            failed_at: Some(NOW + 3600),
            ..Memory::default()
        };
        assert!(may_check(&ahead, false, NOW));
    }

    #[test]
    fn a_dismissed_release_stays_hidden_and_a_newer_one_shows() {
        let dismissed_it = Memory {
            dismissed: Some("v2.3.0".into()),
            ..Memory::default()
        };
        assert_eq!(to_show(parse(AVAILABLE).unwrap(), &dismissed_it), None);
        assert!(to_show(parse(AVAILABLE).unwrap(), &Memory::default()).is_some());
        let newer = with("v2.3.0", "v2.4.0");
        assert!(
            to_show(parse(&newer).unwrap(), &dismissed_it).is_some(),
            "a newer release did not show again"
        );
    }

    /// A folder of its own for one test, removed when the test ends.
    struct Folder(std::path::PathBuf);

    impl Folder {
        fn new(name: &str) -> Folder {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "netdoc-gui-memory-{name}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Folder(dir)
        }

        fn file(&self) -> std::path::PathBuf {
            self.0.join("update")
        }
    }

    impl Drop for Folder {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A save that cannot write is an error, not a silent success. A folder
    /// where the temporary file must go makes the write fail.
    #[test]
    fn a_failed_save_is_an_error_and_the_file_is_unchanged() {
        let folder = Folder::new("failed-save");
        std::fs::create_dir(folder.0.join(format!("update.{}.tmp", std::process::id()))).unwrap();
        assert!(
            change(&folder.file(), |m| m.off = true).is_err(),
            "a failed save looked successful"
        );
        assert!(!folder.file().exists(), "a failed save wrote the file");
    }

    /// Not a test: the work a second process does, when a test asks for it
    /// through the environment. Without the environment it does nothing.
    #[test]
    fn helper_process() {
        let Ok(mode) = std::env::var("NETDOC_UPDATE_HELPER") else {
            return;
        };
        let dir = std::path::PathBuf::from(std::env::var_os("NETDOC_UPDATE_HELPER_DIR").unwrap());
        let file = dir.join("update");
        match mode.as_str() {
            // Fifty increments of a counter kept in `failed_at`, each one a whole change.
            "count" => {
                for _ in 0..50 {
                    change(&file, |m| m.failed_at = Some(m.failed_at.unwrap_or(0) + 1)).unwrap();
                }
            }
            // Holds the lock for a while. It marks "held" once the lock is
            // taken, and "released" just before the change ends.
            "hold" => {
                let hold: u64 = std::env::var("NETDOC_UPDATE_HELPER_HOLD_MS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1000);
                change(&file, |_| {
                    std::fs::write(dir.join("held"), "").unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(hold));
                    std::fs::write(dir.join("released"), "").unwrap();
                })
                .unwrap();
            }
            other => panic!("unknown helper mode {other}"),
        }
    }

    /// Runs this test binary again, as a second process, to do `mode` on `dir`.
    fn spawn_helper(mode: &str, dir: &Path) -> std::process::Child {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "update::tests::helper_process"])
            .env("NETDOC_UPDATE_HELPER", mode)
            .env("NETDOC_UPDATE_HELPER_DIR", dir)
            .spawn()
            .unwrap()
    }

    /// A second process that holds the lock for `hold_ms` milliseconds.
    fn spawn_holder(dir: &Path, hold_ms: u64) -> std::process::Child {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "update::tests::helper_process"])
            .env("NETDOC_UPDATE_HELPER", "hold")
            .env("NETDOC_UPDATE_HELPER_DIR", dir)
            .env("NETDOC_UPDATE_HELPER_HOLD_MS", hold_ms.to_string())
            .spawn()
            .unwrap()
    }

    /// Waits until another process has reached `marker`, or fails the test.
    fn wait_for(marker: &Path) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !marker.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "the other process never reached {}",
                marker.display()
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// Two processes each make fifty changes to one counter. Each change is a
    /// whole transaction under the lock, so none is lost.
    #[test]
    fn two_processes_do_not_lose_each_others_changes() {
        let folder = Folder::new("count");
        let mut a = spawn_helper("count", &folder.0);
        let mut b = spawn_helper("count", &folder.0);
        assert!(a.wait().unwrap().success());
        assert!(b.wait().unwrap().success());
        assert_eq!(
            read(&folder.file()).unwrap().failed_at,
            Some(100),
            "a change was lost between two processes"
        );
    }

    /// A change waits while another process holds the lock, so it runs only
    /// after that process has released.
    #[test]
    fn a_change_waits_for_another_process_to_finish() {
        let folder = Folder::new("wait");
        let mut holder = spawn_holder(&folder.0, 300);
        wait_for(&folder.0.join("held"));
        let released_first = std::cell::Cell::new(false);
        change(&folder.file(), |m| {
            released_first.set(folder.0.join("released").exists());
            m.off = true;
        })
        .unwrap();
        assert!(holder.wait().unwrap().success());
        assert!(
            released_first.get(),
            "a change ran while another process held the lock"
        );
    }

    /// Negative control: without the lock the same change runs while the other
    /// process still holds its change, so the test above is not vacuous.
    #[test]
    fn without_the_lock_a_change_does_not_wait() {
        let folder = Folder::new("no-wait");
        let mut holder = spawn_holder(&folder.0, 1000);
        wait_for(&folder.0.join("held"));
        let released_first = std::cell::Cell::new(false);
        change_without_lock(&folder.file(), |m| {
            released_first.set(folder.0.join("released").exists());
            m.off = true;
        })
        .unwrap();
        assert!(holder.wait().unwrap().success());
        assert!(
            !released_first.get(),
            "the change waited without a lock, so the control proves nothing"
        );
    }

    /// A stalled holder must not freeze a change. The change gives up within the
    /// bound and reports that it could not save, instead of waiting for the holder.
    #[test]
    fn a_stalled_lock_holder_does_not_freeze_a_change() {
        let folder = Folder::new("stalled");
        let mut holder = spawn_holder(&folder.0, 4000);
        wait_for(&folder.0.join("held"));
        let started = std::time::Instant::now();
        let result = change(&folder.file(), |m| m.off = true);
        let elapsed = started.elapsed();
        holder.kill().ok();
        holder.wait().ok();
        let err = result.expect_err("a change waited for a stalled holder instead of giving up");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "the change took {elapsed:?} to give up"
        );
        assert!(
            !folder.file().exists(),
            "a change that gave up still wrote the file"
        );
    }

    /// Negative control: a holder that lets go within the bound is waited out,
    /// so the bound does not refuse every contended change.
    #[test]
    fn a_short_hold_within_the_bound_is_waited_out() {
        let folder = Folder::new("short-hold");
        let mut holder = spawn_holder(&folder.0, 100);
        wait_for(&folder.0.join("held"));
        let released_first = std::cell::Cell::new(false);
        let saved = change(&folder.file(), |m| {
            released_first.set(folder.0.join("released").exists());
            m.off = true;
        });
        assert!(holder.wait().unwrap().success());
        assert!(
            saved.is_ok(),
            "a short hold within the bound refused the change"
        );
        assert!(
            released_first.get(),
            "the change did not wait for the short hold"
        );
    }

    /// An existing preference that cannot be read is an error. A value the file
    /// format does not know is not read as the default.
    #[test]
    fn an_unrecognised_off_value_is_an_error_not_the_default() {
        let folder = Folder::new("bad-off");
        std::fs::write(folder.file(), "off=maybe\n").unwrap();
        assert!(read(&folder.file()).is_err());
        std::fs::write(folder.file(), "off=0\n").unwrap();
        assert!(!read(&folder.file()).unwrap().off, "off=0 is checks on");
    }

    /// Negative control: the same change is saved when nothing blocks the write.
    #[test]
    fn a_change_is_saved_when_the_folder_can_be_written() {
        let folder = Folder::new("saved");
        let m = change(&folder.file(), |m| m.off = true).unwrap();
        assert!(m.off);
        assert!(read(&folder.file()).unwrap().off);
    }

    #[test]
    fn the_opener_takes_the_url_as_one_argument_and_no_shell() {
        let url = "https://github.com/heymaikol/network-doctor/releases/tag/v2.3.0";
        let (program, args) = opener(url);
        assert_eq!(args.last().map(String::as_str), Some(url));
        assert!(
            !matches!(program, "sh" | "bash" | "cmd"),
            "a shell would read the URL: {program}"
        );
        assert_eq!(args.iter().filter(|a| a.contains("v2.3.0")).count(), 1);
    }
}
