// No console window behind the app on Windows.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod look;
mod report;
mod runner;
mod update;

use eframe::egui::{self, Color32, RichText, vec2};
use look::{bad, good, pal, warn};
use report::{Outcome, Report, Tone};
use runner::{Handle, Msg};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc::{Receiver, TryRecvError, channel};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const MAX_HISTORY: usize = 120;
const MAX_WIDTH: f32 = 820.0;
const EXAMPLES: [&str; 3] = ["github.com", "google.com", "wikipedia.org"];
const MODES: [&str; 3] = ["My connection", "A website or server", "A service"];
/// netdoc's built-in service profiles: id, name, needs a target, hint, what it tests.
const PROFILES: [(&str, &str, bool, &str, &str); 4] = [
    (
        "github",
        "GitHub",
        false,
        "",
        "Tests GitHub's website, its API, SSH, and SSH over port 443, each on its own. Useful when pushing or cloning fails.",
    ),
    (
        "web",
        "A website",
        true,
        "e.g. example.com",
        "Tests the secure (HTTPS) and the plain (HTTP) version of a site separately.",
    ),
    (
        "ssh",
        "An SSH server",
        true,
        "e.g. myserver.lan",
        "Tests an SSH server: its name, the route to it, the connection and its greeting.",
    ),
    (
        "smtp",
        "A mail server",
        true,
        "e.g. smtp.example.com",
        "Tests a mail server's sending ports separately.",
    ),
];

fn tone_color(t: Tone) -> Color32 {
    match t {
        Tone::Good => good(),
        Tone::Warn => warn(),
        Tone::Bad => bad(),
        Tone::Muted => pal().weak,
    }
}

fn symbol(status: &str) -> &'static str {
    match status {
        "PASS" => "✔",
        "WARN" => "!",
        "FAIL" | "INCOMPLETE" => "✖",
        _ => "–",
    }
}

fn weak(t: impl Into<String>) -> RichText {
    RichText::new(t.into()).color(pal().weak)
}

/// A rounded "Online" style pill with a dot, like net-watch's header.
fn pill(ui: &mut egui::Ui, color: Color32, text: &str) {
    let galley =
        ui.painter()
            .layout_no_wrap(text.to_string(), egui::FontId::proportional(16.0), color);
    let size = vec2(galley.size().x + 52.0, 36.0);
    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
    let p = ui.painter();
    p.rect_filled(rect, 18.0, color.gamma_multiply(0.14));
    let c = egui::pos2(rect.left() + 20.0, rect.center().y);
    p.circle_filled(c, 6.0, color);
    p.galley(
        egui::pos2(rect.left() + 36.0, rect.center().y - galley.size().y / 2.0),
        galley,
        color,
    );
}

fn ago(t: Instant) -> String {
    let s = t.elapsed().as_secs();
    match s {
        0..=4 => "just now".into(),
        5..=59 => format!("{s} s ago"),
        60..=3599 => format!("{} min ago", s / 60),
        _ => format!("{} h ago", s / 3600),
    }
}

/// The error to show when netdoc ends without a report. A healthy or problem
/// exit (0 or 1) has a report, and a stop the user asked for is not an error.
fn exit_error(code: Option<i32>, stderr: &str, stopped_by_user: bool) -> Option<String> {
    if matches!(code, Some(0) | Some(1)) || stopped_by_user {
        return None;
    }
    let msg = stderr.trim();
    Some(if msg.is_empty() {
        "netdoc stopped without a result.".into()
    } else {
        msg.to_string()
    })
}

/// The user's home folder: %USERPROFILE% on Windows, $HOME elsewhere.
fn home_dir() -> Option<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Where the chosen theme is kept: %APPDATA% on Windows, Application Support
/// on macOS, the XDG config folder elsewhere.
fn config_file() -> Option<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)?
    } else if cfg!(target_os = "macos") {
        home_dir()?.join("Library").join("Application Support")
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| home_dir().map(|h| h.join(".config")))?
    };
    Some(base.join("netdoc-gui").join("theme"))
}

/// Where the update check keeps what the window remembers: beside the theme.
/// The warning when there is no config folder to keep the update setting in.
const NO_SETTINGS_FOLDER: &str =
    "No settings folder was found, so this change lasts only until this window closes.";

fn memory_file() -> Option<PathBuf> {
    config_file().map(|p| p.with_file_name("update"))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load_theme() -> usize {
    if let Some(i) = std::env::var("NETDOC_GUI_THEME")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        return i;
    }
    config_file()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn save_theme(i: usize) {
    if let Some(p) = config_file() {
        let _ = std::fs::create_dir_all(p.parent().unwrap());
        let _ = std::fs::write(p, i.to_string());
    }
}

struct App {
    netdoc: Option<PathBuf>,
    netdoc_version: Option<String>,
    /// The version check, until its answer arrives.
    version_rx: Option<Receiver<Option<String>>>,
    /// 0 = my connection, 1 = a website or server.
    mode: usize,
    target: String,
    watch: bool,
    interval: u32,
    details: bool,
    show_settings: bool,
    theme: usize,
    running: Option<Handle>,
    /// Messages from the current check only. Each check gets a new channel,
    /// so nothing from an earlier one can reach the window.
    rx: Option<Receiver<Msg>>,
    /// The user pressed Stop, so the run ending is not an error.
    stop_requested: bool,
    /// The running export: its stop handle, its worker, and its messages.
    saving: Option<(Handle, std::thread::JoinHandle<()>)>,
    save_rx: Option<Receiver<Msg>>,
    /// The profile and target of the check on screen. Export uses these, not the
    /// form, so the file belongs to the result the user is looking at.
    run_args: (Option<String>, Option<String>),
    /// Shared, so showing a report each frame doesn't copy it.
    history: Vec<(Instant, Rc<Outcome>)>,
    /// Which service profile is chosen, and which of its parts is open.
    profile: usize,
    part: Option<usize>,
    /// Whether the evidence behind the diagnosis is shown.
    why: bool,
    shown: Option<usize>,
    error: Option<String>,
    note: Option<(String, bool)>,
    /// A failure after a report. It stays until the next check starts, so a
    /// notice such as an export message cannot cover it.
    failure: Option<String>,
    ctx: egui::Context,
    /// NETDOC_GUI_SCREENSHOT=file.ppm: save the window, then quit.
    screenshot: Option<(String, u32)>,
    /// What the update check remembers, and the file it lives in.
    memory: update::Memory,
    memory_path: Option<PathBuf>,
    /// Why the last change to the update setting was not kept, while it is not.
    memory_warning: Option<String>,
    /// The user's choices this session that the file does not hold yet.
    pending: update::Pending,
    /// NETDOC_NO_UPDATE_CHECK=1 is set, which holds the switch off.
    update_env_opt_out: bool,
    /// The newer release the banner shows, if any.
    update: Option<update::Release>,
    /// The update check's answer, until it arrives, and the probe that is asking.
    update_rx: Option<Receiver<Option<String>>>,
    update_probe: Option<runner::Handle>,
    /// How the release page opens. A test replaces it.
    open_page: fn(&str) -> bool,
}

/// How the window starts. The real window reads these from its surroundings
/// (`Startup::from_env`); anything else, such as a test, states them.
#[derive(Default)]
struct Startup {
    netdoc: Option<PathBuf>,
    theme: usize,
    target: String,
    mode: Option<usize>,
    profile: usize,
    why: bool,
    watch: bool,
    /// Start a check as soon as the window opens.
    autorun: bool,
    /// Save the window to this file, then quit.
    screenshot: Option<String>,
    /// Ask netdoc for a newer release at launch, subject to the update memory.
    update_check: bool,
    update_memory: Option<PathBuf>,
    /// NETDOC_NO_UPDATE_CHECK=1 is set, which turns the launch check off.
    update_env_opt_out: bool,
}

impl Startup {
    /// The installed netdoc, the saved theme, and the NETDOC_GUI_* variables.
    fn from_env() -> Self {
        Startup {
            netdoc: runner::find_netdoc(),
            theme: load_theme(),
            target: std::env::var("NETDOC_GUI_TARGET").unwrap_or_default(),
            mode: std::env::var("NETDOC_GUI_MODE")
                .ok()
                .and_then(|m| m.parse().ok())
                .filter(|m| *m < MODES.len()),
            profile: std::env::var("NETDOC_GUI_PROFILE")
                .ok()
                .and_then(|p| PROFILES.iter().position(|x| x.0 == p))
                .unwrap_or(0),
            why: std::env::var_os("NETDOC_GUI_WHY").is_some(),
            watch: std::env::var_os("NETDOC_GUI_WATCH").is_some(),
            autorun: std::env::var_os("NETDOC_GUI_AUTORUN").is_some(),
            screenshot: std::env::var("NETDOC_GUI_SCREENSHOT").ok(),
            update_check: true,
            update_memory: memory_file(),
            update_env_opt_out: std::env::var("NETDOC_NO_UPDATE_CHECK").is_ok_and(|v| v == "1"),
        }
    }
}

impl App {
    fn new(ctx: egui::Context, startup: Startup) -> Self {
        let Startup {
            netdoc,
            theme,
            target,
            mode,
            profile,
            why,
            watch,
            autorun,
            screenshot,
            update_check,
            update_memory,
            update_env_opt_out,
        } = startup;
        look::set_theme(&ctx, theme);
        look::install(&ctx);
        let version_rx = netdoc.clone().map(|bin| {
            let ctx = ctx.clone();
            runner::start_version(bin, move || ctx.request_repaint())
        });
        let memory = update_memory
            .as_deref()
            .map(update::load)
            .unwrap_or_default();
        let mut app = App {
            netdoc,
            netdoc_version: None,
            version_rx,
            profile,
            part: None,
            why,
            mode: mode.unwrap_or(if target.is_empty() { 0 } else { 1 }),
            target,
            watch,
            interval: 5,
            details: false,
            show_settings: false,
            theme,
            running: None,
            rx: None,
            stop_requested: false,
            saving: None,
            save_rx: None,
            run_args: (None, None),
            history: vec![],
            shown: None,
            error: None,
            note: None,
            failure: None,
            ctx,
            screenshot: screenshot.map(|p| (p, 0)),
            memory,
            memory_path: update_memory,
            memory_warning: None,
            pending: update::Pending::default(),
            update_env_opt_out,
            update: None,
            update_rx: None,
            update_probe: None,
            open_page: update::open_page,
        };
        // Once per launch, unless the user, the environment, or an earlier failure says no.
        if update_check
            && let Some(bin) = app.netdoc.clone()
            && update::may_check(&app.memory, update_env_opt_out, now_secs())
        {
            let ctx = app.ctx.clone();
            let (probe, answer) = runner::start_update_check(bin, move || ctx.request_repaint());
            app.update_probe = Some(probe);
            app.update_rx = Some(answer);
        }
        // The same rule as the Check button: a target-based check needs a target.
        if autorun && app.can_check() {
            app.start();
        }
        app
    }

    /// Whether the chosen kind of check is about a target the user names.
    fn wants_target(&self) -> bool {
        match self.mode {
            0 => false,
            2 => PROFILES[self.profile].2,
            _ => true,
        }
    }

    fn target_arg(&self) -> Option<String> {
        let t = self.target.trim();
        (self.wants_target() && !t.is_empty()).then(|| t.to_string())
    }

    fn profile_arg(&self) -> Option<String> {
        (self.mode == 2).then(|| PROFILES[self.profile].0.to_string())
    }

    fn can_check(&self) -> bool {
        self.netdoc.is_some()
            && self.running.is_none()
            && (!self.wants_target() || !self.target.trim().is_empty())
    }

    fn start(&mut self) {
        let Some(bin) = self.netdoc.clone() else {
            return;
        };
        // One check at a time: a second start would orphan the first one's handle.
        if self.running.is_some() {
            return;
        }
        self.error = None;
        self.note = None;
        self.failure = None;
        self.history.clear();
        self.shown = None;
        self.part = None;
        self.stop_requested = false;
        let (tx, rx) = channel();
        self.rx = Some(rx);
        let ctx = self.ctx.clone();
        let watch = self.watch.then_some(self.interval);
        self.run_args = (self.profile_arg(), self.target_arg());
        self.running = Some(runner::run(
            bin,
            self.run_args.0.clone(),
            self.run_args.1.clone(),
            watch,
            tx,
            move || ctx.request_repaint(),
        ));
    }

    fn stop(&mut self) {
        if let Some(h) = &self.running {
            h.stop();
            self.stop_requested = true;
        }
    }

    fn export(&mut self) {
        let Some(bin) = self.netdoc.clone() else {
            return;
        };
        if self.saving.is_some() {
            return;
        }
        let home = home_dir().unwrap_or_else(|| PathBuf::from("."));
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let dest = home.join(format!("network-doctor-report-{stamp}.ndoc"));
        self.note = Some((
            "Writing the report… it runs the checks again, so give it a few seconds.".into(),
            false,
        ));
        let (tx, rx) = channel();
        self.save_rx = Some(rx);
        let ctx = self.ctx.clone();
        let stop = Handle::default();
        let join = runner::save_support(
            stop.clone(),
            bin,
            self.run_args.0.clone(),
            self.run_args.1.clone(),
            dest,
            tx,
            move || ctx.request_repaint(),
        );
        self.saving = Some((stop, join));
    }

    fn poll(&mut self) {
        self.poll_check();
        self.poll_save();
    }

    /// Takes the update check's answer once it has arrived. An unanswered check
    /// is remembered, so the next launch waits; any other valid answer clears that.
    fn poll_update(&mut self) {
        let Some(rx) = self.update_rx.as_ref() else {
            return;
        };
        let text = match rx.try_recv() {
            Ok(text) => text,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => None,
        };
        self.update_rx = None;
        self.update_probe = None;
        let Some(answer) = text.as_deref().and_then(update::parse) else {
            return;
        };
        let failed = matches!(answer, update::Answer::Unanswered).then(now_secs);
        self.change_memory(|m| m.failed_at = failed);
        self.update = update::to_show(answer, &self.memory);
    }

    /// Makes one change to the update memory against the file as it is now, so
    /// a window that loaded the file earlier cannot undo another window's change.
    /// The window shows the change either way. When it is not kept, a warning
    /// says it lasts only until the window closes.
    fn change_memory(&mut self, change: impl Fn(&mut update::Memory)) {
        let Some(path) = self.memory_path.clone() else {
            change(&mut self.memory);
            self.pending.apply(&mut self.memory);
            self.pending = update::Pending::default();
            self.memory_warning = Some(NO_SETTINGS_FOLDER.to_string());
            return;
        };
        let pending = self.pending.clone();
        match update::change(&path, |m| {
            change(m);
            pending.apply(m);
        }) {
            Ok(m) => {
                self.memory = m;
                self.pending = update::Pending::default();
                self.memory_warning = None;
            }
            Err(e) => {
                change(&mut self.memory);
                self.pending.apply(&mut self.memory);
                self.memory_warning = Some(format!(
                    "Could not save the update setting ({e}), so this change lasts only until this window closes."
                ));
            }
        }
    }

    /// Turns automatic update checks on or off, as the Settings switch does. The
    /// choice is kept until it is saved, even if this save fails.
    fn set_update_check(&mut self, on: bool) {
        self.pending.off = Some(!on);
        self.change_memory(|_| {});
    }

    /// Records that the user dismissed the banner for this release.
    fn dismiss_update(&mut self) {
        if let Some(r) = self.update.take() {
            self.pending.dismissed = Some(r.latest);
            self.change_memory(|_| {});
        }
    }

    /// Shows why the last change to the update setting was not kept, so an
    /// unsaved setting never looks saved.
    fn memory_warning_line(&self, ui: &mut egui::Ui) {
        let Some(text) = self.memory_warning.as_deref() else {
            return;
        };
        ui.add_space(8.0);
        ui.add(egui::Label::new(RichText::new(text).color(bad())).wrap());
    }

    /// Opens the release page the banner names. If it can't open, says where it is.
    fn open_update_page(&mut self) {
        let Some(r) = self.update.as_ref() else {
            return;
        };
        if !(self.open_page)(&r.url) {
            self.note = Some((
                format!("Couldn't open the release page. Its address is {}", r.url),
                true,
            ));
        }
    }

    /// The passive notice for a newer release. It takes no focus and blocks nothing.
    fn update_banner(&mut self, ui: &mut egui::Ui) {
        let Some(r) = self.update.as_ref() else {
            return;
        };
        let text = format!(
            "Network Doctor {} is available. You have {}.",
            r.latest, r.installed
        );
        ui.add_space(8.0);
        look::card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(text).strong());
                if look::button(ui, "Open release page", true, true).clicked() {
                    self.open_update_page();
                }
                if look::button(ui, "Dismiss", false, true).clicked() {
                    self.dismiss_update();
                }
            });
        });
    }

    /// Takes the version check's answer once it has arrived.
    fn poll_version(&mut self) {
        let Some(rx) = self.version_rx.as_ref() else {
            return;
        };
        match rx.try_recv() {
            Ok(v) => {
                self.netdoc_version = v;
                self.version_rx = None;
            }
            Err(TryRecvError::Disconnected) => self.version_rx = None,
            Err(TryRecvError::Empty) => {}
        }
    }

    fn poll_check(&mut self) {
        let Some(rx) = self.rx.take() else {
            return;
        };
        loop {
            match rx.try_recv() {
                Ok(Msg::Report(r)) => {
                    self.history.push((Instant::now(), Rc::new(r)));
                    if self.history.len() > MAX_HISTORY {
                        self.history.remove(0);
                        self.shown = self.shown.and_then(|i| i.checked_sub(1));
                    }
                }
                // Only Finished ends the check: a failure can still have netdoc running.
                // With a report on screen the failure goes beside it, in the status
                // bar, so the last result stays readable.
                Ok(Msg::Failed(e)) if self.history.is_empty() => self.error = Some(e),
                Ok(Msg::Failed(e)) => self.failure = Some(e),
                Ok(Msg::Finished { code, stderr }) => return self.finish_check(code, &stderr),
                Ok(Msg::Saved(_)) => {}
                Err(TryRecvError::Empty) => {
                    self.rx = Some(rx);
                    return;
                }
                // The worker ended without its Finished: don't leave "Checking…" up.
                Err(TryRecvError::Disconnected) => return self.finish_check(None, ""),
            }
        }
    }

    fn finish_check(&mut self, code: Option<i32>, stderr: &str) {
        self.running = None;
        if self.history.is_empty() && self.error.is_none() {
            self.error = exit_error(code, stderr, self.stop_requested);
        }
    }

    fn poll_save(&mut self) {
        let Some(rx) = self.save_rx.take() else {
            return;
        };
        loop {
            match rx.try_recv() {
                Ok(Msg::Saved(Ok(p))) => {
                    self.saving = None;
                    self.note = Some((
                        format!(
                            "Saved {}. It is a fresh diagnostic run, so it may differ from the result on screen. Read it before sending it to anyone: it can still mention your network.",
                            p.display()
                        ),
                        false,
                    ));
                    return;
                }
                Ok(Msg::Saved(Err(e))) => {
                    self.saving = None;
                    self.note = Some((e, true));
                    return;
                }
                Ok(_) => {}
                Err(TryRecvError::Empty) => {
                    self.save_rx = Some(rx);
                    return;
                }
                Err(TryRecvError::Disconnected) => {
                    self.saving = None;
                    self.note = Some(("The report wasn't written.".into(), true));
                    return;
                }
            }
        }
    }

    fn current(&self) -> Option<&(Instant, Rc<Outcome>)> {
        let i = self.shown.unwrap_or(self.history.len().checked_sub(1)?);
        self.history.get(i)
    }

    fn take_screenshot(&mut self, ui: &egui::Ui) {
        let Some((path, frames)) = &mut self.screenshot else {
            return;
        };
        if *frames == u32::MAX {
            let image = ui.input(|i| {
                i.raw.events.iter().find_map(|ev| match ev {
                    egui::Event::Screenshot { image, .. } => Some(image.clone()),
                    _ => None,
                })
            });
            if let Some(image) = image {
                let mut ppm = format!("P6 {} {} 255\n", image.size[0], image.size[1]).into_bytes();
                for px in &image.pixels {
                    ppm.extend_from_slice(&[px.r(), px.g(), px.b()]);
                }
                // Only ever a new file: an environment variable must not be able to overwrite one.
                let written = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&*path)
                    .and_then(|mut f| std::io::Write::write_all(&mut f, &ppm));
                if let Err(e) = written {
                    eprintln!("screenshot not saved to {path}: {e}");
                }
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
            }
            return;
        }
        *frames += 1;
        ui.ctx().request_repaint();
        let checked = !self.history.is_empty()
            && (self.running.is_none() || self.watch && self.history.len() >= 4);
        if (checked && *frames > 40) || *frames > 3600 {
            *frames = u32::MAX;
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::Screenshot(Default::default()));
        }
    }

    fn header(&mut self, ui: &mut egui::Ui) {
        ui.add_space(14.0);
        ui.horizontal(|ui| {
            ui.add_space(4.0);
            let (color, text) = match (&self.running, self.current()) {
                (Some(_), None) => (pal().accent, "Checking…".to_string()),
                (_, Some((_, o))) => (tone_color(o.tone()), o.pill().to_string()),
                (None, None) => (pal().weak, "Not checked yet".to_string()),
            };
            pill(ui, color, &text);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.label(RichText::new("Network Doctor").size(17.0).strong());
                let when = match (&self.running, self.current()) {
                    (Some(_), _) if self.watch => "Watching, checks every few seconds".to_string(),
                    (Some(_), _) => "Checking now…".to_string(),
                    (None, Some((t, _))) => format!("Checked {}", ago(*t)),
                    _ => "A friendly face for the netdoc network checker".to_string(),
                };
                ui.label(RichText::new(when).small().color(pal().weak));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(4.0);
                let gear = look::button(ui, "⚙", false, true);
                gear.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, "Settings"));
                if gear.on_hover_text("Settings").clicked() {
                    self.show_settings = !self.show_settings;
                }
                if look::button(ui, "Export report", true, self.netdoc.is_some() && self.running.is_none() && self.saving.is_none() && self.current().is_some())
                    .on_hover_text("Saves a privacy-reduced report of this check, for whoever is helping you. It runs the same check again for the same target. Nothing is uploaded.")
                    .clicked()
                {
                    self.export();
                }
            });
        });
        ui.add_space(12.0);
    }

    fn settings(&mut self, ui: &mut egui::Ui) {
        look::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(look::caption("Settings"));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if look::chip(ui, "Done", true, true).clicked() {
                        self.show_settings = false;
                    }
                });
            });
            ui.label("Theme");
            ui.horizontal_wrapped(|ui| {
                for (i, (name, theme)) in look::THEMES.iter().enumerate() {
                    let swatch = look::swatch(ui, theme, i == self.theme);
                    swatch.widget_info(|| {
                        egui::WidgetInfo::selected(
                            egui::WidgetType::RadioButton,
                            true,
                            i == self.theme,
                            *name,
                        )
                    });
                    if swatch.on_hover_text(*name).clicked() {
                        self.theme = i;
                        look::set_theme(ui.ctx(), i);
                        save_theme(i);
                    }
                }
            });
            ui.add_space(6.0);
            // With NETDOC_NO_UPDATE_CHECK=1 set, the switch shows off and ignores clicks.
            let env_off = self.update_env_opt_out;
            let mut check = !self.memory.off && !env_off;
            ui.add_enabled_ui(!env_off, |ui| {
                ui.horizontal(|ui| {
                    if look::toggle(ui, "Check for updates when the window opens", &mut check)
                        .changed()
                        && !env_off
                    {
                        self.set_update_check(check);
                    }
                    ui.label("Check for updates when the window opens");
                });
            });
            if env_off {
                ui.label(weak("Off in this environment: NETDOC_NO_UPDATE_CHECK=1 is set. Unset it to use this switch.").small());
            }
            ui.label(weak("Asks GitHub once a launch for a newer release. NETDOC_NO_UPDATE_CHECK=1 also turns it off.").small());
            ui.label(
                weak("GitHub receives the public IP address this request originates from, which may be a proxy's.").small(),
            );
            match (&self.netdoc, &self.netdoc_version) {
                (Some(p), Some(v)) => {
                    ui.label(weak(format!("Checks are run by {v} ({})", p.display())).small())
                }
                (Some(_), None) if self.version_rx.is_some() => {
                    ui.label(weak("Checking netdoc's version…").small())
                }
                (Some(p), None) => ui.label(
                    weak(format!(
                        "Checks are run by netdoc ({}); its version couldn't be read.",
                        p.display()
                    ))
                    .small(),
                ),
                _ => ui.label(weak("netdoc wasn't found.").small()),
            };
            ui.label(weak("This is an unofficial front-end. Network Doctor itself is made by its own authors: github.com/heymaikol/network-doctor").small());
        });
        ui.add_space(12.0);
    }

    fn what_to_check(&mut self, ui: &mut egui::Ui) {
        let running = self.running.is_some();
        look::card(ui, |ui| {
            ui.label(look::caption("What to check"));
            ui.add_enabled_ui(!running, |ui| {
                look::tabs(ui, "mode", &mut self.mode, &MODES);
                match self.mode {
                    0 => {
                        ui.label(weak("Tests this computer's connection: the network, the way out to the internet, and names (DNS)."));
                    }
                    1 => {
                        self.target_box(ui, "e.g. github.com, or a server like myserver.lan:22");
                        ui.horizontal_wrapped(|ui| {
                            ui.label(weak("Try:").small());
                            for ex in EXAMPLES {
                                if look::chip(ui, ex, true, true).clicked() {
                                    self.target = ex.to_string();
                                }
                            }
                        });
                    }
                    _ => {
                        let names: Vec<&str> = PROFILES.iter().map(|p| p.1).collect();
                        look::tabs(ui, "profile", &mut self.profile, &names);
                        let (_, _, needs_target, hint, about) = PROFILES[self.profile];
                        ui.add(egui::Label::new(weak(about)).wrap());
                        if needs_target {
                            self.target_box(ui, hint);
                        }
                    }
                }
                ui.horizontal(|ui| {
                    look::toggle(ui, "Keep watching", &mut self.watch).on_hover_text("Keep checking, to catch problems that come and go");
                    ui.label("Keep watching");
                    if self.watch {
                        ui.label(weak("every"));
                        ui.add(egui::DragValue::new(&mut self.interval).range(1..=3600).suffix(" s"));
                    } else {
                        ui.label(weak("for problems that come and go").small());
                    }
                });
            });
        });
        ui.add_space(12.0);
    }

    fn target_box(&mut self, ui: &mut egui::Ui, hint: &str) {
        let edit = ui.add(
            egui::TextEdit::singleline(&mut self.target)
                .hint_text(hint)
                .desired_width(f32::INFINITY),
        );
        // egui names a text field by its hint. Give it a real name, and keep its
        // current text in the tree, which a bare label override would drop.
        let (enabled, text) = (ui.is_enabled(), self.target.clone());
        edit.widget_info(|| {
            let mut info = egui::WidgetInfo::text_edit(enabled, &text, &text, hint);
            info.label = Some("Address to check".to_string());
            info
        });
        if edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && self.can_check() {
            self.start();
        }
    }

    /// A service profile's parts, with the chosen one's steps shown below.
    fn parts(&mut self, ui: &mut egui::Ui, p: &report::ProfileReport, part: usize) {
        ui.add_space(4.0);
        let (tone, word) = match p.aggregate.status.as_str() {
            "PASS" => (Tone::Good, "everything works"),
            "WARN" => (Tone::Warn, "partly working"),
            _ => (Tone::Bad, "not working"),
        };
        ui.label(
            RichText::new(format!("{}: {word}", p.title))
                .size(17.0)
                .color(tone_color(tone)),
        );
        ui.add(egui::Label::new(&p.aggregate.summary).wrap());
        for (i, c) in p.components.iter().enumerate() {
            let col = tone_color(c.tone());
            let resp = egui::Frame::new()
                .fill(if i == part {
                    pal().accent_soft
                } else {
                    pal().key.gamma_multiply(0.5)
                })
                .corner_radius(8)
                .inner_margin(egui::Margin::symmetric(10, 6))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        let (rect, _) =
                            ui.allocate_exact_size(vec2(22.0, 22.0), egui::Sense::hover());
                        ui.painter().circle_filled(
                            rect.center(),
                            11.0,
                            col.gamma_multiply(if pal().light { 0.14 } else { 0.22 }),
                        );
                        let mark = match c.tone() {
                            Tone::Good => "✔",
                            Tone::Warn => "!",
                            _ => "✖",
                        };
                        ui.painter().text(
                            rect.center(),
                            egui::Align2::CENTER_CENTER,
                            mark,
                            egui::FontId::proportional(12.5),
                            col,
                        );
                        ui.label(RichText::new(&c.label).strong());
                        if let Some(t) = &c.target {
                            ui.label(RichText::new(&t.host).small().color(pal().weak));
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(RichText::new(c.word()).small().color(col));
                        });
                    });
                })
                .response;
            // The row is one control: a choice among the parts, named after its
            // part and its status, that Enter or Space picks like a click does.
            let row = ui.interact(resp.rect, ui.id().with(("part", i)), egui::Sense::click());
            row.widget_info(|| {
                egui::WidgetInfo::selected(
                    egui::WidgetType::RadioButton,
                    true,
                    i == part,
                    format!("{}: {}", c.label, c.word()),
                )
            });
            if row.has_focus() {
                ui.painter().rect_stroke(
                    resp.rect.expand(3.0),
                    11.0,
                    egui::Stroke::new(2.0, pal().accent),
                    egui::StrokeKind::Outside,
                );
            }
            if row
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .clicked()
            {
                self.part = Some(i);
            }
        }
        ui.label(weak("Pick a part to see its steps.").small());
        ui.separator();
        if let Some(c) = p.components.get(part) {
            ui.label(look::caption(&c.label));
        }
    }

    fn diagnosis(&mut self, ui: &mut egui::Ui) {
        let running = self.running.is_some();
        let current = self.current().cloned();
        let part = current
            .as_ref()
            .map(|(_, o)| self.part.unwrap_or(o.first_problem()))
            .unwrap_or(0);
        look::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(look::caption("What's wrong?"));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if running {
                        if look::button(ui, "Stop", false, true).clicked() {
                            self.stop();
                        }
                        // A spinner redraws the window 60 times a second. While
                        // watching that would go on for hours, so it only spins
                        // until the first result is in.
                        if self.watch && current.is_some() {
                            ui.label(weak("watching").small());
                        } else {
                            ui.spinner();
                        }
                    } else {
                        let label = match (&current, self.mode) {
                            (Some(_), _) => "Check again".to_string(),
                            (None, 0) => "Check my connection".to_string(),
                            (None, 2) if !PROFILES[self.profile].2 => format!("Check {}", PROFILES[self.profile].1),
                            (None, _) if self.target.trim().is_empty() => "Check".to_string(),
                            (None, _) => format!("Check {}", self.target.trim()),
                        };
                        if look::button(ui, &label, true, self.can_check()).clicked() {
                            self.start();
                        }
                        if let Some(r) = current.as_ref().and_then(|(_, o)| o.detail(part))
                            && look::chip(ui, "Copy report", true, true).on_hover_text("Copy the result and every step. The text is not redacted: it can include addresses and network names.").clicked() {
                                ui.ctx().copy_text(report::as_text(r));
                                self.note = Some(("Copied. The text is not redacted, so check it before you send it. For a privacy-reduced file, use Export report.".into(), false));
                            }
                    }
                });
            });

            if let Some(e) = &self.error {
                ui.label(
                    RichText::new("netdoc couldn't run the check")
                        .size(17.0)
                        .color(bad()),
                );
                ui.add(egui::Label::new(RichText::new(e).monospace().small()).wrap());
                return;
            }
            let Some((_, outcome)) = current else {
                if self.netdoc.is_none() {
                    ui.label(
                        RichText::new("netdoc isn't installed")
                            .size(17.0)
                            .color(warn()),
                    );
                    ui.add(egui::Label::new(weak("This app shows the results of Network Doctor's netdoc program. Install it from github.com/heymaikol/network-doctor/releases, or set NETDOC to where it is.")).wrap());
                } else if running {
                    ui.label(RichText::new("Checking…").size(17.0));
                    ui.label(weak("This takes a few seconds."));
                } else {
                    ui.add(egui::Label::new(weak(
                        "Checks the connection one step at a time, from this computer out to the internet and the site you name: \
                         the network, the way out, names (DNS), the secure connection and the site itself. It stops where things \
                         break and says what to try.",
                    )).wrap());
                }
                return;
            };

            let r: &Report = match &*outcome {
                Outcome::Single(r) => r,
                Outcome::Profile(p) => {
                    self.parts(ui, p, part);
                    match p.components.get(part).and_then(|c| c.report.as_ref()) {
                        Some(r) => r,
                        None => return,
                    }
                }
            };

            // The answer first, a little tighter than the theme's spacing.
            ui.spacing_mut().item_spacing.y = 6.0;
            ui.spacing_mut().interact_size.y = 20.0;
            ui.add_space(4.0);
            let (head, explain, tone) = report::headline(r);
            ui.label(RichText::new(head).size(17.0).color(tone_color(tone)));
            ui.add(egui::Label::new(&r.summary).wrap());
            if !r.healthy() {
                ui.add(egui::Label::new(weak(explain)).wrap());
            }

            // What to try.
            for f in &r.findings {
                let Some(rem) = &f.remediation else { continue };
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Try:").strong());
                    ui.label(RichText::new(&rem.action).strong());
                    let ct = match f.confidence.as_str() {
                        "high" => good(),
                        "medium" => warn(),
                        _ => pal().weak,
                    };
                    ui.label(
                        RichText::new(report::confidence_word(&f.confidence).to_lowercase())
                            .small()
                            .color(ct),
                    )
                    .on_hover_text("How sure Network Doctor is that this is the cause");
                    if !f.causal_evidence.is_empty()
                        && look::chip(ui, if self.why { "Hide why" } else { "Why?" }, true, true)
                            .on_hover_text("The evidence behind this answer")
                            .clicked()
                    {
                        self.why = !self.why;
                    }
                });
                if let Some(why) = &rem.why {
                    ui.add(egui::Label::new(weak(why)).wrap());
                }
                for (i, s) in rem.steps.iter().enumerate() {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(format!("{}.", i + 1))
                                .color(pal().accent)
                                .strong(),
                        );
                        ui.add(egui::Label::new(s).wrap());
                    });
                }
                if !rem.command.is_empty() {
                    let line = report::shell_line(&rem.command);
                    ui.horizontal(|ui| {
                        egui::Frame::new()
                            .fill(pal().key)
                            .corner_radius(8)
                            .inner_margin(egui::Margin::symmetric(10, 5))
                            .show(ui, |ui| {
                                ui.label(RichText::new(&line).monospace());
                            });
                        if look::chip(ui, "Copy", true, true)
                            .on_hover_text(
                                "Run it yourself in a terminal. It only looks, it changes nothing.",
                            )
                            .clicked()
                        {
                            ui.ctx().copy_text(line.clone());
                            self.note = Some((
                                format!("Copied \"{line}\". Paste it into a terminal to run it."),
                                false,
                            ));
                        }
                    });
                }
                if let Some(e) = &rem.expect {
                    ui.add(egui::Label::new(weak(format!("Fixed when: {e}")).small()).wrap());
                }
                if self.why && !f.causal_evidence.is_empty() {
                    let why = report::why(f, r);
                    egui::Frame::new()
                        .fill(pal().key.gamma_multiply(0.5))
                        .corner_radius(8)
                        .inner_margin(egui::Margin::symmetric(12, 8))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(look::caption("Why Network Doctor thinks so"));
                            ui.add(
                                egui::Label::new(weak(report::confidence_means(&f.confidence)))
                                    .wrap(),
                            );
                            for (title, lines, color) in [
                                ("What points to it", &why.supports, good()),
                                ("Ruled out", &why.ruled_out, pal().accent),
                                ("Less likely, but still possible", &why.weakened, warn()),
                                ("Couldn't be checked", &why.unchecked, pal().weak),
                            ] {
                                if lines.is_empty() {
                                    continue;
                                }
                                ui.label(RichText::new(title).strong().color(color));
                                for l in lines {
                                    ui.horizontal_wrapped(|ui| {
                                        ui.label(RichText::new("•").color(color));
                                        ui.add(egui::Label::new(l).wrap());
                                    });
                                }
                            }
                        });
                }
                if let Some(url) = r.checks.iter().find_map(|c| {
                    c.portal
                        .as_ref()?
                        .redirect_url
                        .as_deref()
                        .map(report::clean)
                }) {
                    ui.horizontal_wrapped(|ui| {
                        ui.label("The network's sign-in page:");
                        ui.label(RichText::new(&url).monospace());
                        if look::chip(ui, "Copy", true, true).clicked() {
                            ui.ctx().copy_text(url.clone());
                        }
                    });
                    ui.add(egui::Label::new(weak(
                        "This address comes from the network, not from Network Doctor. Only open it on a network you expect a \
                         sign-in page from (a hotel, café or airport), and never enter passwords for other accounts there.",
                    ).small()).wrap());
                }
            }
            ui.add_space(6.0);
            ui.separator();

            // Every step, as net-watch shows them.
            ui.horizontal(|ui| {
                ui.label(look::caption("Step by step"));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    look::toggle(ui, "Show details", &mut self.details);
                    ui.label(weak("Show details"));
                });
            });
            for c in &r.checks {
                let quiet = matches!(c.status.as_str(), "SKIP" | "N/A");
                ui.scope(|ui| {
                    if quiet {
                        ui.multiply_opacity(0.55);
                    }
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 10.0;
                        let (rect, _) =
                            ui.allocate_exact_size(vec2(22.0, 22.0), egui::Sense::hover());
                        let col = tone_color(report::status_tone(&c.status));
                        ui.painter().circle_filled(
                            rect.center(),
                            11.0,
                            col.gamma_multiply(if pal().light { 0.14 } else { 0.22 }),
                        );
                        ui.painter().text(
                            rect.center(),
                            egui::Align2::CENTER_CENTER,
                            symbol(&c.status),
                            egui::FontId::proportional(12.5),
                            col,
                        );
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 1.0;
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(&c.title).strong()).widget_info(|| {
                                    egui::WidgetInfo::labeled(
                                        egui::WidgetType::Label,
                                        true,
                                        format!("{}: {}", c.title, report::status_word(&c.status)),
                                    )
                                });
                                if r.failed_stage.as_deref() == Some(c.id.as_str()) {
                                    ui.label(RichText::new("stopped here").small().color(col));
                                }
                            });
                            let says = c.says.as_str();
                            let says = if matches!(c.status.as_str(), "FAIL" | "WARN") {
                                RichText::new(says)
                            } else {
                                weak(says)
                            };
                            ui.add(egui::Label::new(says).wrap());
                        });
                    });
                    if self.details && !quiet {
                        ui.horizontal(|ui| {
                            ui.add_space(32.0);
                            ui.spacing_mut().interact_size.y = 0.0;
                            egui::Grid::new(("details", &c.id))
                                .num_columns(2)
                                .min_col_width(110.0)
                                .spacing(vec2(14.0, 3.0))
                                .show(ui, |ui| {
                                    let mut row = |k: &str, v: String| {
                                        ui.label(RichText::new(k).small().color(pal().weak));
                                        ui.add(
                                            egui::Label::new(RichText::new(v).small().monospace())
                                                .wrap(),
                                        );
                                        ui.end_row();
                                    };
                                    row("Check", c.name.clone());
                                    if !c.detail.is_empty() {
                                        row("Found", c.detail.clone());
                                    }
                                    if c.ms > 0 {
                                        row("Took", format!("{} ms", c.ms));
                                    }
                                    if let Some(cause) = &c.cause {
                                        row("Cause", cause.clone());
                                    }
                                    if !c.addrs.is_empty() {
                                        row("Addresses", c.addrs.join(", "));
                                    }
                                });
                        });
                    }
                });
                ui.add_space(4.0);
            }
        });
        ui.add_space(12.0);
    }

    fn history_card(&mut self, ui: &mut egui::Ui) {
        if self.history.len() < 2 && !(self.watch && self.running.is_some()) {
            return;
        }
        let problems = self.history.iter().filter(|(_, r)| !r.ok()).count();
        look::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(look::caption("History"));
                ui.label(
                    weak(format!(
                        "{} checks · {}",
                        self.history.len(),
                        match problems {
                            0 => "no problems".to_string(),
                            1 => "1 with a problem".to_string(),
                            n => format!("{n} with a problem"),
                        }
                    ))
                    .small(),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.shown.is_some() && look::chip(ui, "Show latest", true, true).clicked() {
                        self.shown = None;
                    }
                });
            });
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 3.0;
                let current = self.shown.unwrap_or(self.history.len().saturating_sub(1));
                for (i, (t, r)) in self.history.iter().enumerate() {
                    let c = tone_color(r.tone());
                    let (rect, resp) =
                        ui.allocate_exact_size(vec2(9.0, 22.0), egui::Sense::click());
                    ui.painter().rect_filled(
                        rect,
                        3.0,
                        if i == current {
                            c
                        } else {
                            c.gamma_multiply(0.45)
                        },
                    );
                    // Built only for the bar the pointer is on.
                    if resp
                        .on_hover_ui(|ui| {
                            ui.label(format!("{}\n{}", ago(*t), r.summary()));
                        })
                        .clicked()
                    {
                        self.shown = Some(i);
                        self.part = None;
                    }
                }
            });
            ui.label(
                weak("Each bar is one check, newest on the right. Click one to see it.").small(),
            );
        });
        ui.add_space(12.0);
    }
}

impl App {
    /// The whole window, drawn into `ui`. Tests drive this without a native window.
    fn show(&mut self, ui: &mut egui::Ui) {
        self.poll();
        self.poll_version();
        self.poll_update();
        self.take_screenshot(ui);
        egui::Panel::top("top")
            .frame(
                egui::Frame::new()
                    .fill(pal().bg)
                    .inner_margin(egui::Margin::symmetric(16, 0)),
            )
            .show(ui, |ui| {
                self.header(ui);
                self.update_banner(ui);
                self.memory_warning_line(ui);
            });
        egui::Panel::bottom("status").frame(egui::Frame::new().fill(pal().bg).inner_margin(egui::Margin::symmetric(16, 6))).show(ui, |ui| {
            if let Some(f) = &self.failure {
                ui.add(egui::Label::new(RichText::new(f).small().color(bad())).wrap());
            }
            match &self.note {
                Some((n, err)) => {
                    ui.add(egui::Label::new(RichText::new(n).small().color(if *err { bad() } else { pal().text })).wrap());
                }
                None if self.failure.is_none() => {
                    ui.label(weak("Results come from Network Doctor (netdoc). This window only shows them.").small());
                }
                None => {}
            }
        });
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(pal().bg)
                    .inner_margin(egui::Margin::symmetric(16, 0)),
            )
            .show(ui, |ui| {
                let mut area = egui::ScrollArea::vertical().auto_shrink(false);
                // For screenshots: start scrolled down.
                if let (Some(_), Some(y)) = (
                    &self.screenshot,
                    std::env::var("NETDOC_GUI_SCROLL")
                        .ok()
                        .and_then(|v| v.parse::<f32>().ok()),
                ) {
                    area = area.vertical_scroll_offset(y);
                }
                area.show(ui, |ui| {
                    let w = ui.available_width().min(MAX_WIDTH);
                    ui.vertical_centered(|ui| {
                        ui.set_max_width(w);
                        ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                            if self.show_settings {
                                self.settings(ui);
                            }
                            self.what_to_check(ui);
                            self.history_card(ui);
                            self.diagnosis(ui);
                        });
                    });
                });
            });
        // Keeps "Checked 9 s ago" current: it counts seconds for the first
        // minute, then minutes, so the window can sleep longer after that.
        if let Some((t, _)) = self.current() {
            let secs = if t.elapsed().as_secs() < 60 { 1 } else { 30 };
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_secs(secs));
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.show(ui);
    }
}

impl Drop for App {
    fn drop(&mut self) {
        self.stop();
        if let Some(probe) = self.update_probe.take() {
            probe.stop();
        }
        // Closing the window waits for a running export to stop and remove its
        // claimed file. netdoc exits within moments of SIGTERM, so this is short.
        if let Some((h, join)) = self.saving.take() {
            h.stop();
            let _ = join.join();
        }
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 820.0])
            .with_min_inner_size([520.0, 420.0])
            .with_icon(
                eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon.png"))
                    .unwrap_or_default(),
            )
            .with_app_id("io.github.heymaikol.netdoc-gui"),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    eframe::run_native(
        "Network Doctor",
        options,
        Box::new(|cc| Ok(Box::new(App::new(cc.egui_ctx.clone(), Startup::from_env())))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One result, as netdoc prints it on a single line.
    #[cfg(unix)]
    const REPORT_LINE: &str =
        r#"{"version":"x","target":null,"checks":[],"summary":"x","verdict":"ok","ok":true}"#;

    /// A stand-in netdoc. `--version` gets its own answer, so the version probe
    /// never runs the check body.
    #[cfg(unix)]
    fn fake_netdoc(dir: &std::path::Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("netdoc-fake");
        let script = format!(
            "#!/bin/sh\ncase \"$1\" in\n--version) echo 'netdoc test'; exit 0;;\nesac\n{body}\n"
        );
        std::fs::write(&p, script).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// A fresh directory for one test, removed by the test when it ends.
    #[cfg(unix)]
    fn scratch_dir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("netdoc-gui-{name}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A check that is still waiting for netdoc's update answer holds nothing: a
    /// diagnostic started meanwhile finishes, and the window stays in its hands.
    #[cfg(unix)]
    #[test]
    fn a_pending_update_check_does_not_hold_a_diagnostic() {
        let dir = scratch_dir("update-and-run");
        let body =
            format!("case \"$1\" in\n-update-check) exec sleep 600;;\nesac\necho '{REPORT_LINE}'");
        let startup = Startup {
            netdoc: Some(fake_netdoc(&dir, &body)),
            update_check: true,
            ..Startup::default()
        };
        let mut app = App::new(egui::Context::default(), startup);
        assert!(app.update_rx.is_some(), "the update check did not start");
        app.start();
        let ended = wait_for_the_check(&mut app);
        let reports = app.history.len();
        // The update answer is still pending, so the diagnostic ran alongside it.
        let still_pending = app.update_rx.is_some();
        drop(app);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(ended, "the diagnostic waited for the pending update check");
        assert_eq!(reports, 1, "the diagnostic produced no report");
        assert!(
            still_pending,
            "the update check had finished first, so this proved nothing"
        );
    }

    /// A window whose next check runs `body` as netdoc, with the watch setting given.
    #[cfg(unix)]
    fn window_running(dir: &std::path::Path, body: &str, watch: bool) -> App {
        let startup = Startup {
            netdoc: Some(fake_netdoc(dir, body)),
            watch,
            ..Startup::default()
        };
        App::new(egui::Context::default(), startup)
    }

    /// Takes the check's messages, as the frames would, until the check ends.
    /// False if it has not ended in thirty seconds.
    #[cfg(unix)]
    fn wait_for_the_check(app: &mut App) -> bool {
        let started = Instant::now();
        while app.running.is_some() {
            if started.elapsed() > std::time::Duration::from_secs(30) {
                return false;
            }
            app.poll_check();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        true
    }

    /// W6: a one-shot check whose output ends with a complete report, and whose
    /// process then never exits, keeps its report and says nothing.
    #[cfg(unix)]
    #[test]
    fn w6_a_one_shot_that_expires_after_its_report_stays_quiet() {
        let dir = scratch_dir("w6");
        let body = format!("echo '{REPORT_LINE}'\nexec >&- 2>&-\nexec sleep 60");
        let mut app = window_running(&dir, &body, false);
        app.start();
        let ended = wait_for_the_check(&mut app);
        let (reports, failure, error) = (app.history.len(), app.failure.clone(), app.error.clone());
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(ended, "the check never ended");
        assert_eq!(reports, 1, "the report was lost");
        assert!(
            failure.is_none() && error.is_none(),
            "the expiry was said: {failure:?} {error:?}"
        );
    }

    /// W7: a check that started as a one-shot stays one when Keep watching is
    /// turned on while it runs.
    #[cfg(unix)]
    #[test]
    fn w7_turning_watch_on_mid_run_does_not_change_a_one_shot() {
        let dir = scratch_dir("w7-on");
        let body = format!("echo '{REPORT_LINE}'\nsleep 1\nexit 1");
        let mut app = window_running(&dir, &body, false);
        app.start();
        app.watch = true; // the toggle, changed while the check runs
        let ended = wait_for_the_check(&mut app);
        let (reports, failure, error) = (app.history.len(), app.failure.clone(), app.error.clone());
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(ended, "the check never ended");
        assert_eq!(reports, 1, "the report was lost");
        assert!(
            failure.is_none() && error.is_none(),
            "a one-shot was read as a watch: {failure:?} {error:?}"
        );
    }

    /// W7: a check that started as a watch stays one when Keep watching is
    /// turned off while it runs, so its unexpected end is still said.
    #[cfg(unix)]
    #[test]
    fn w7_turning_watch_off_mid_run_does_not_change_a_watch() {
        let dir = scratch_dir("w7-off");
        let body = format!("echo '{REPORT_LINE}'\nsleep 1\nexit 0");
        let mut app = window_running(&dir, &body, true);
        app.start();
        app.watch = false; // the toggle, changed while the check runs
        let ended = wait_for_the_check(&mut app);
        let (reports, failure) = (app.history.len(), app.failure.clone());
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(ended, "the check never ended");
        assert_eq!(reports, 1, "the report was lost");
        assert!(
            failure
                .as_deref()
                .is_some_and(|f| f.contains("stopped watching unexpectedly")),
            "the watch's unexpected end was not said: {failure:?}"
        );
    }

    #[test]
    fn only_an_unexplained_end_is_an_error() {
        // A stop the user asked for is quiet, whatever netdoc exited with.
        assert_eq!(exit_error(None, "", true), None);
        assert_eq!(exit_error(Some(2), "boom", true), None);
        // 0 and 1 both come with a report.
        assert_eq!(exit_error(Some(1), "", false), None);
        assert_eq!(exit_error(None, " boom \n", false), Some("boom".into()));
        assert_eq!(
            exit_error(None, "", false),
            Some("netdoc stopped without a result.".into())
        );
    }
}

/// The window driven headlessly through its accessibility tree: names,
/// roles and keyboard use, as an assistive technology would see them.
#[cfg(test)]
mod access {
    use super::*;
    use egui::accesskit::Role;
    use egui_kittest::Harness;
    use egui_kittest::kittest::{NodeT, Queryable};

    /// Writes the stand-in netdoc into `dir`. It answers `--version`, which
    /// `App::new` asks for, and records anything else in `dir/invoked`.
    #[cfg(unix)]
    fn write_stub(dir: &std::path::Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let bin = dir.join("netdoc");
        let log = dir.join("invoked");
        std::fs::write(
            &bin,
            format!(
                "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'netdoc test stub'; exit 0; fi\necho \"$*\" >> '{}'\nexit 2\n",
                log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        bin
    }

    #[cfg(windows)]
    fn write_stub(dir: &std::path::Path) -> PathBuf {
        let bin = dir.join("netdoc.bat");
        let log = dir.join("invoked");
        std::fs::write(
            &bin,
            format!(
                "@echo off\r\nif \"%~1\"==\"--version\" (echo netdoc test stub) else (echo %* >> \"{}\")\r\n",
                log.display()
            ),
        )
        .unwrap();
        bin
    }

    /// Runs the named test in a process of its own, with NETDOC pointing at a
    /// stand-in netdoc in a fresh directory. The variable is set on that child
    /// only, never on this process, so the stub cannot reach any other test.
    fn run_in_stub_process(child: &str) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("netdoc-gui-stub-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let stub = write_stub(&dir);
        let before = std::env::var_os("NETDOC");
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", child])
            .env("NETDOC", &stub)
            .env("NETDOC_GUI_STUB_CHILD", "1")
            .output()
            .unwrap();
        let after = std::env::var_os("NETDOC");
        // The child writes this last. Without it the child ran nothing: a wrong name
        // makes libtest run zero tests and still report success.
        let finished = dir.join("finished").exists();
        std::fs::remove_dir_all(&dir).unwrap();
        // This process's environment must be unchanged: the stub stays in the child.
        assert_eq!(after, before, "the stub leaked into this process");
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(finished, "the child test {child} never reached its end");
    }

    /// The stand-in netdoc, in the child process the helper starts. The helper
    /// hands the path over in NETDOC; the window is given it directly.
    fn stub() -> PathBuf {
        PathBuf::from(std::env::var_os("NETDOC").expect("run by the stub-process helper"))
    }

    /// The stand-in netdoc's record of checks, read by the child process.
    fn stub_log() -> PathBuf {
        stub().with_file_name("invoked")
    }

    /// Whether the stand-in netdoc has been asked to run a check.
    fn checks_started() -> bool {
        stub_log().exists()
    }

    /// Lets the window run for half a second, so a check started by a focus
    /// change has time to reach the stub.
    fn settle(h: &mut Harness<'static, App>) {
        let started = std::time::Instant::now();
        while started.elapsed() < std::time::Duration::from_millis(500) {
            h.step();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// A window with stated startup options and no netdoc. Nothing is read
    /// from the environment, so an installed netdoc, a saved theme or a
    /// NETDOC_GUI_* variable in the test run cannot change what is tested.
    fn window() -> Harness<'static, App> {
        window_with(None)
    }

    fn window_with(netdoc: Option<PathBuf>) -> Harness<'static, App> {
        let startup = Startup {
            netdoc,
            ..Startup::default()
        };
        Harness::new_ui_state(
            |ui, app: &mut App| app.show(ui),
            App::new(egui::Context::default(), startup),
        )
    }

    #[test]
    fn a_failure_after_a_report_survives_an_export_notice() {
        let mut app = App::new(egui::Context::default(), Startup::default());
        let outcome = report::parse(include_str!("../tests/fixtures/healthy.json")).unwrap();
        app.history.push((Instant::now(), Rc::new(outcome)));
        let (tx, rx) = channel();
        tx.send(Msg::Failed("the bad line".into())).unwrap();
        app.rx = Some(rx);
        app.poll_check();
        assert_eq!(app.failure.as_deref(), Some("the bad line"));
        assert!(
            app.error.is_none() && app.history.len() == 1,
            "the report was covered"
        );
        // An export finishing afterwards writes its own notice, not over the failure.
        let (tx, rx) = channel();
        tx.send(Msg::Saved(Ok(PathBuf::from("/tmp/netdoc-report.json"))))
            .unwrap();
        app.save_rx = Some(rx);
        app.poll_save();
        assert!(app.note.is_some(), "the export notice was not shown");
        assert_eq!(
            app.failure.as_deref(),
            Some("the bad line"),
            "the export notice covered the failure"
        );
    }

    #[test]
    fn a_new_check_clears_the_last_failure() {
        let mut app = App::new(egui::Context::default(), Startup::default());
        app.failure = Some("an old failure".into());
        app.netdoc = Some(PathBuf::from("/nonexistent/netdoc"));
        app.start();
        assert!(app.failure.is_none(), "the old failure is still shown");
    }

    #[test]
    fn autorun_without_a_target_starts_nothing() {
        // A website or server check with no target would show a generic result
        // under the wrong heading. The Check button refuses it, so autorun must too.
        let startup = Startup {
            netdoc: Some(PathBuf::from("/nonexistent/netdoc")),
            autorun: true,
            mode: Some(1),
            ..Startup::default()
        };
        let app = App::new(egui::Context::default(), startup);
        assert!(app.running.is_none(), "a check started with no target");
    }

    #[test]
    fn autorun_with_a_target_starts_its_check() {
        let startup = Startup {
            netdoc: Some(PathBuf::from("/nonexistent/netdoc")),
            autorun: true,
            mode: Some(1),
            target: "github.com".into(),
            ..Startup::default()
        };
        let app = App::new(egui::Context::default(), startup);
        assert!(app.running.is_some(), "autorun with a target did not start");
    }

    #[test]
    fn startup_options_do_not_come_from_the_environment() {
        let h = window();
        let app = h.state();
        assert!(app.netdoc.is_none() && app.version_rx.is_none());
        assert!(app.running.is_none(), "a check started on its own");
        assert!(app.screenshot.is_none());
        assert_eq!((app.mode, app.theme, app.watch), (0, 0, false));
    }

    /// Whether a choice is the selected one. egui reports that as "toggled".
    fn chosen(node: &egui_kittest::Node<'_>) -> bool {
        node.accesskit_node().toggled() == Some(egui::accesskit::Toggled::True)
    }

    #[test]
    fn each_part_of_a_profile_is_a_named_choice_the_keyboard_can_pick() {
        let mut h = window();
        let outcome = report::parse(include_str!("../tests/fixtures/profile-web.json")).unwrap();
        let Outcome::Profile(p) = &outcome else {
            panic!("not a profile")
        };
        let names: Vec<String> = p
            .components
            .iter()
            .map(|c| format!("{}: {}", c.label, c.word()))
            .collect();
        assert!(names.len() > 1, "the fixture needs more than one part");
        let first = outcome.first_problem();
        h.state_mut()
            .history
            .push((Instant::now(), Rc::new(outcome)));
        h.run();
        // The part opened first is the selected one, and only that one.
        for (i, name) in names.iter().enumerate() {
            let row = h.get_by_role_and_label(Role::RadioButton, name);
            assert_eq!(chosen(&row), i == first, "{name}");
        }
        // Enter on another part opens that part's steps.
        let other = (first + 1) % names.len();
        h.get_by_role_and_label(Role::RadioButton, &names[other])
            .focus();
        h.run();
        h.key_press(egui::Key::Enter);
        h.run();
        assert_eq!(h.state().part, Some(other));
        let row = h.get_by_role_and_label(Role::RadioButton, &names[other]);
        assert!(chosen(&row), "the picked part is not the selected one");
    }

    #[test]
    fn a_failure_after_a_report_is_shown_beside_it() {
        let mut h = window();
        let (tx, rx) = channel();
        let outcome = report::parse(include_str!("../tests/fixtures/healthy.json")).unwrap();
        tx.send(Msg::Report(outcome)).unwrap();
        tx.send(Msg::Failed("netdoc was stopped.".into())).unwrap();
        h.state_mut().rx = Some(rx);
        h.run();
        let app = h.state();
        assert_eq!(app.history.len(), 1);
        assert!(app.error.is_none(), "the failure replaced the report");
        assert_eq!(app.failure.as_deref(), Some("netdoc was stopped."));
        // It is drawn in the status bar, beside the report.
        h.run();
        h.get_by_label("netdoc was stopped.");
    }

    #[test]
    fn the_main_controls_have_names_and_roles() {
        let mut h = window();
        h.run();
        h.get_by_role_and_label(Role::Button, "Settings");
        h.get_by_role_and_label(Role::Button, "Export report");
        h.get_by_role_and_label(Role::Button, "Check my connection");
        h.get_by_role_and_label(Role::RadioButton, "My connection");
        h.get_by_role_and_label(Role::RadioButton, "A website or server");
        h.get_by_role_and_label(Role::RadioButton, "A service");
        h.get_by_role_and_label(Role::CheckBox, "Keep watching");
    }

    #[test]
    fn the_theme_swatches_are_named() {
        let mut h = window();
        h.state_mut().show_settings = true;
        h.run();
        for (name, _) in look::THEMES.iter() {
            h.get_by_role_and_label(Role::RadioButton, name);
        }
    }

    /// The switch draws no text of its own, so the words beside it are a
    /// visible label, not only the name a screen reader hears.
    #[test]
    fn the_update_switch_has_a_visible_label() {
        let mut h = window();
        h.state_mut().show_settings = true;
        h.run();
        h.get_by_role_and_label(Role::Label, "Check for updates when the window opens");
    }

    /// The Settings say who receives the request, so the privacy line is visible.
    #[test]
    fn the_settings_say_github_receives_the_public_address() {
        let mut h = window();
        h.state_mut().show_settings = true;
        h.run();
        h.get_by_role_and_label(
            Role::Label,
            "GitHub receives the public IP address this request originates from, which may be a proxy's.",
        );
    }

    #[test]
    fn the_settings_button_opens_from_the_keyboard() {
        let mut h = window();
        h.run();
        h.get_by_role_and_label(Role::Button, "Settings").focus();
        h.run();
        h.key_press(egui::Key::Enter);
        h.run();
        assert!(
            h.state().show_settings,
            "Enter on the focused Settings button did nothing"
        );
    }

    #[test]
    fn the_target_field_has_a_name_and_its_text() {
        let mut h = window();
        h.state_mut().mode = 1;
        h.state_mut().target = "github.com".into();
        h.run();
        let field = h.get_by_role_and_label(Role::TextInput, "Address to check");
        assert_eq!(field.value().as_deref(), Some("github.com"));
    }

    #[test]
    fn each_step_exposes_its_status_word() {
        // The status is a symbol on screen; the tree must carry the word too.
        let mut h = window();
        let outcome = report::parse(include_str!("../tests/fixtures/degraded.json")).unwrap();
        h.state_mut()
            .history
            .push((Instant::now(), Rc::new(outcome)));
        h.run();
        h.get_by_label("Large data gets through: Warning");
        h.get_by_label("Reaches the internet: OK");
    }

    #[test]
    fn a_finished_export_says_it_is_a_fresh_run() {
        let mut h = window();
        let (tx, rx) = channel();
        tx.send(Msg::Saved(Ok(PathBuf::from("/tmp/report.ndoc"))))
            .unwrap();
        h.state_mut().save_rx = Some(rx);
        h.run();
        let note = h
            .state()
            .note
            .clone()
            .map(|(text, _)| text)
            .unwrap_or_default();
        assert!(
            note.contains("fresh diagnostic run"),
            "the export note doesn't say so: {note}"
        );
    }

    #[test]
    fn tab_reaches_every_main_control() {
        run_in_stub_process("access::tab_reaches_every_main_control_child");
    }

    /// The body of the test above. Run as an ordinary test it does nothing: it
    /// acts only in the child process that the helper starts.
    #[test]
    fn tab_reaches_every_main_control_child() {
        if std::env::var_os("NETDOC_GUI_STUB_CHILD").is_none() {
            return;
        }
        // With a result on screen Export is enabled; before one, it is rightly
        // disabled and cannot take focus.
        let mut h = window_with(Some(stub()));
        let outcome = report::parse(include_str!("../tests/fixtures/healthy.json")).unwrap();
        h.state_mut()
            .history
            .push((Instant::now(), Rc::new(outcome)));
        // Mode 1 with a target renders the target field, which Tab must pass through.
        h.state_mut().mode = 1;
        h.state_mut().target = "github.com".into();
        h.run();
        let controls = [
            (Role::Button, "Settings"),
            (Role::Button, "Export report"),
            (Role::RadioButton, "My connection"),
            (Role::RadioButton, "A website or server"),
            (Role::RadioButton, "A service"),
            (Role::CheckBox, "Keep watching"),
            (Role::TextInput, "Address to check"),
            (Role::Button, "Check again"),
        ];
        let mut reached = vec![false; controls.len()];
        for _ in 0..80 {
            h.key_press(egui::Key::Tab);
            // Not run(): a check started by a focus change keeps the spinner repainting.
            h.run_steps(4);
            for (i, (role, name)) in controls.iter().enumerate() {
                // query, not get: a control can vanish while a check runs, and the
                // invariant below should be what reports that.
                if h.query_by_role_and_label(*role, name)
                    .is_some_and(|node| node.is_focused())
                {
                    reached[i] = true;
                }
            }
        }
        // Focus into the target field with Tab, then away from it with Tab.
        let mut in_field = false;
        for _ in 0..40 {
            if h.query_by_role_and_label(Role::TextInput, "Address to check")
                .is_some_and(|node| node.is_focused())
            {
                in_field = true;
                break;
            }
            h.key_press(egui::Key::Tab);
            h.run_steps(4);
        }
        h.key_press(egui::Key::Tab);
        h.run_steps(4);
        // Moving focus must start no diagnostic check. App::new's version probe
        // is not a check, and the stub records only checks. Settle first: a check
        // started by a focus change reaches the stub a moment after the change.
        settle(&mut h);
        assert!(
            !checks_started(),
            "moving focus into or out of the target field started a check"
        );
        assert!(in_field, "Tab never reached the target field");
        let missed: Vec<&str> = controls
            .iter()
            .zip(&reached)
            .filter(|(_, got)| !**got)
            .map(|((_, name), _)| *name)
            .collect();
        assert!(missed.is_empty(), "Tab never reached: {missed:?}");
        // Control: Enter on the focused Check button must start one, or the
        // assertion above would prove nothing.
        h.get_by_role_and_label(Role::Button, "Check again").focus();
        h.run();
        h.key_press(egui::Key::Enter);
        let waited = std::time::Instant::now();
        while !checks_started() && waited.elapsed() < std::time::Duration::from_secs(10) {
            // One frame at a time: a running check keeps the window repainting.
            h.step();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(checks_started(), "Enter on Check again started no check");
        std::fs::write(stub_log().with_file_name("finished"), "").unwrap();
    }

    #[test]
    fn tab_reaches_a_mode_choice_and_enter_selects_it() {
        let mut h = window();
        h.run();
        for _ in 0..60 {
            if h.get_by_role_and_label(Role::RadioButton, "A service")
                .is_focused()
            {
                break;
            }
            h.key_press(egui::Key::Tab);
            h.run();
        }
        assert!(
            h.get_by_role_and_label(Role::RadioButton, "A service")
                .is_focused(),
            "Tab never reached the A service choice"
        );
        h.key_press(egui::Key::Enter);
        h.run();
        assert_eq!(
            h.state().mode,
            2,
            "Enter on the focused choice did not select it"
        );
    }
}

#[cfg(test)]
mod update_notice {
    use super::*;
    use egui::accesskit::Role;
    use egui_kittest::Harness;
    use egui_kittest::kittest::Queryable;
    use std::path::Path;
    use std::sync::Mutex;

    const AVAILABLE: &str = include_str!("../tests/fixtures/update-available.json");
    const OFFLINE: &str = include_str!("../tests/fixtures/update-offline.json");

    /// A window that starts no check of its own, remembering in `memory`.
    fn app(memory: Option<PathBuf>) -> App {
        let startup = Startup {
            update_memory: memory,
            ..Startup::default()
        };
        App::new(egui::Context::default(), startup)
    }

    /// The memory file for one test, in a folder of its own.
    fn memory_in_a_fresh_folder(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "netdoc-gui-update-{name}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("update")
    }

    fn cleanup(memory: &Path) {
        let _ = std::fs::remove_dir_all(memory.parent().unwrap());
    }

    /// A channel that already holds `text` as the check's answer.
    fn answer(text: &str) -> Receiver<Option<String>> {
        let (tx, rx) = channel();
        tx.send(Some(text.to_string())).unwrap();
        rx
    }

    #[test]
    fn a_newer_release_shows_the_banner_once_answered() {
        let mut a = app(None);
        a.update_rx = Some(answer(AVAILABLE));
        a.poll_update();
        let r = a.update.clone().expect("the banner did not show");
        assert_eq!(r.latest, "v2.3.0");
        assert!(a.update_rx.is_none());
    }

    #[test]
    fn dismissing_hides_the_release_across_a_restart_and_a_newer_one_shows() {
        let path = memory_in_a_fresh_folder("dismiss");
        let mut first = app(Some(path.clone()));
        first.update_rx = Some(answer(AVAILABLE));
        first.poll_update();
        first.dismiss_update();
        assert!(first.update.is_none());

        let mut second = app(Some(path.clone()));
        second.update_rx = Some(answer(AVAILABLE));
        second.poll_update();
        assert!(
            second.update.is_none(),
            "the dismissed banner came back after a restart"
        );

        let newer = AVAILABLE.replace("v2.3.0", "v2.4.0");
        let mut third = app(Some(path.clone()));
        third.update_rx = Some(answer(&newer));
        third.poll_update();
        assert_eq!(
            third.update.as_ref().map(|r| r.latest.as_str()),
            Some("v2.4.0")
        );
        cleanup(&path);
    }

    #[test]
    fn an_unanswered_check_is_remembered_and_holds_the_next_launch() {
        let path = memory_in_a_fresh_folder("offline");
        let mut a = app(Some(path.clone()));
        a.update_rx = Some(answer(OFFLINE));
        a.poll_update();
        assert!(a.update.is_none());
        assert!(
            a.memory.failed_at.is_some(),
            "the failure was not remembered"
        );
        assert!(
            !update::may_check(&update::load(&path), false, now_secs()),
            "the next launch would ask again at once"
        );
        cleanup(&path);
    }

    #[test]
    fn a_broken_answer_or_no_answer_changes_nothing() {
        let path = memory_in_a_fresh_folder("broken");
        let mut a = app(Some(path.clone()));
        a.update_rx = Some(answer("{\"schema\":\"something-else\"}"));
        a.poll_update();
        assert!(a.update.is_none());
        assert_eq!(a.memory, update::Memory::default());
        assert!(!path.exists(), "a broken answer wrote the memory");

        let (tx, rx) = channel::<Option<String>>();
        drop(tx);
        a.update_rx = Some(rx);
        a.poll_update();
        assert!(
            a.update_rx.is_none(),
            "a check that ended without an answer kept waiting"
        );
        assert!(a.update.is_none());
        cleanup(&path);
    }

    static OPENED: Mutex<Vec<String>> = Mutex::new(Vec::new());

    fn record_open(url: &str) -> bool {
        OPENED.lock().unwrap().push(url.to_string());
        true
    }

    fn refuse_open(_url: &str) -> bool {
        false
    }

    #[test]
    fn opening_the_release_page_passes_the_checked_url() {
        let mut a = app(None);
        a.open_page = record_open;
        a.update_rx = Some(answer(AVAILABLE));
        a.poll_update();
        a.open_update_page();
        assert_eq!(
            *OPENED.lock().unwrap(),
            vec!["https://github.com/heymaikol/network-doctor/releases/tag/v2.3.0".to_string()]
        );
    }

    #[test]
    fn a_refused_open_says_where_the_release_page_is() {
        let mut a = app(None);
        a.open_page = refuse_open;
        a.update_rx = Some(answer(AVAILABLE));
        a.poll_update();
        a.open_update_page();
        let (note, is_error) = a.note.clone().expect("no note");
        assert!(is_error);
        assert!(
            note.contains("releases/tag/v2.3.0"),
            "the note hides the address: {note}"
        );
    }

    #[test]
    fn the_launch_check_starts_only_when_allowed() {
        let missing = Some(PathBuf::from("/nonexistent/netdoc-for-a-test"));
        let no_check = App::new(
            egui::Context::default(),
            Startup {
                netdoc: missing.clone(),
                ..Startup::default()
            },
        );
        assert!(
            no_check.update_rx.is_none(),
            "a launch without the check asked netdoc"
        );
        let env_off = App::new(
            egui::Context::default(),
            Startup {
                netdoc: missing.clone(),
                update_check: true,
                update_env_opt_out: true,
                ..Startup::default()
            },
        );
        assert!(
            env_off.update_rx.is_none(),
            "NETDOC_NO_UPDATE_CHECK=1 was ignored"
        );
        let allowed = App::new(
            egui::Context::default(),
            Startup {
                netdoc: missing,
                update_check: true,
                ..Startup::default()
            },
        );
        assert!(
            allowed.update_rx.is_some(),
            "the launch check did not start"
        );
    }

    /// Two windows on one memory file. Window B loaded the file before window A
    /// turned checks off, so B's copy still says they are on. B's later writes
    /// must leave A's setting alone.
    #[test]
    fn a_stale_window_does_not_undo_another_windows_setting() {
        let path = memory_in_a_fresh_folder("two-windows");
        let mut a = app(Some(path.clone()));
        let mut b = app(Some(path.clone()));
        a.set_update_check(false);
        b.update_rx = Some(answer(OFFLINE));
        b.poll_update();
        let disk = update::load(&path);
        assert!(disk.off, "a stale window wrote checks back on");
        assert!(
            disk.failed_at.is_some(),
            "the failed check was not recorded"
        );
        b.update_rx = Some(answer(AVAILABLE));
        b.poll_update();
        b.dismiss_update();
        let disk = update::load(&path);
        assert!(
            disk.off,
            "a stale window wrote checks back on after a dismissal"
        );
        assert_eq!(
            disk.dismissed.as_deref(),
            Some("v2.3.0"),
            "the dismissal was not saved"
        );
        cleanup(&path);
    }

    /// Negative control: the stale window's own switch still works, so the fix
    /// does not make the setting sticky.
    #[test]
    fn a_stale_window_can_still_turn_checks_back_on() {
        let path = memory_in_a_fresh_folder("stale-own");
        let mut a = app(Some(path.clone()));
        let mut b = app(Some(path.clone()));
        a.set_update_check(false);
        b.set_update_check(true);
        assert!(
            !update::load(&path).off,
            "the stale window could not turn checks back on"
        );
        cleanup(&path);
    }

    /// With NETDOC_NO_UPDATE_CHECK=1 the switch is shown off and explained, and
    /// clicking it stores nothing, so the environment never becomes a stored choice.
    #[test]
    fn the_switch_is_off_and_inert_under_the_environment_opt_out() {
        let path = memory_in_a_fresh_folder("env-off");
        let startup = Startup {
            update_memory: Some(path.clone()),
            update_env_opt_out: true,
            ..Startup::default()
        };
        let mut h = Harness::new_ui_state(
            |ui, app: &mut App| app.show(ui),
            App::new(egui::Context::default(), startup),
        );
        h.state_mut().show_settings = true;
        h.run();
        h.get_by_role_and_label(
            Role::Label,
            "Off in this environment: NETDOC_NO_UPDATE_CHECK=1 is set. Unset it to use this switch.",
        );
        h.get_by_role_and_label(Role::CheckBox, "Check for updates when the window opens")
            .click();
        h.run();
        assert!(!h.state().memory.off, "the switch changed the setting");
        assert!(!path.exists(), "the environment wrote the stored setting");
        cleanup(&path);
    }

    /// A change the window cannot save is still shown, and the window says it
    /// lasts only until it closes, so an unsaved setting never looks saved.
    #[test]
    fn a_change_that_cannot_be_saved_is_warned_not_hidden() {
        let path = memory_in_a_fresh_folder("unsaved");
        // A folder where the temporary file must go makes the save fail.
        std::fs::create_dir(path.with_file_name(format!("update.{}.tmp", std::process::id())))
            .unwrap();
        let mut h =
            Harness::new_ui_state(|ui, app: &mut App| app.show(ui), app(Some(path.clone())));
        h.state_mut().show_settings = true;
        h.run();
        h.get_by_role_and_label(Role::CheckBox, "Check for updates when the window opens")
            .click();
        h.run();
        assert!(
            h.state().memory.off,
            "the change is not shown for this session"
        );
        assert!(!path.exists(), "a failed save wrote the file");
        h.get_by_label_contains("Could not save the update setting");
        h.get_by_label_contains("lasts only until this window closes");
        cleanup(&path);
    }

    /// Negative control: a change that is saved shows no warning.
    #[test]
    fn a_saved_change_shows_no_warning() {
        let path = memory_in_a_fresh_folder("saved-warning");
        let mut h =
            Harness::new_ui_state(|ui, app: &mut App| app.show(ui), app(Some(path.clone())));
        h.state_mut().show_settings = true;
        h.run();
        h.get_by_role_and_label(Role::CheckBox, "Check for updates when the window opens")
            .click();
        h.run();
        assert!(update::load(&path).off, "the setting was not saved");
        assert!(
            h.query_by_label_contains("Could not save the update setting")
                .is_none()
        );
        assert!(h.state().memory_warning.is_none());
        cleanup(&path);
    }

    /// Without a config folder the change lasts only for this session, and the
    /// window says so.
    #[test]
    fn without_a_settings_folder_the_change_is_warned() {
        let mut h = Harness::new_ui_state(|ui, app: &mut App| app.show(ui), app(None));
        h.state_mut().show_settings = true;
        h.run();
        h.get_by_role_and_label(Role::CheckBox, "Check for updates when the window opens")
            .click();
        h.run();
        assert!(
            h.state().memory.off,
            "the change is not shown for this session"
        );
        h.get_by_label_contains("No settings folder was found");
    }

    /// A change that could not be saved is the user's explicit choice for this
    /// session. A later save that does not touch it must not discard it.
    #[test]
    fn a_failed_opt_out_survives_a_later_save_that_does_not_change_it() {
        let path = memory_in_a_fresh_folder("pending-save");
        let conflict = path.with_file_name(format!("update.{}.tmp", std::process::id()));
        std::fs::create_dir(&conflict).unwrap();
        let mut h =
            Harness::new_ui_state(|ui, app: &mut App| app.show(ui), app(Some(path.clone())));
        h.state_mut().show_settings = true;
        h.run();
        h.get_by_role_and_label(Role::CheckBox, "Check for updates when the window opens")
            .click();
        h.run();
        assert!(h.state().memory.off, "the failed change is not shown");
        // The folder is writable again. A later answer changes only the failure time.
        std::fs::remove_dir(&conflict).unwrap();
        h.state_mut().update_rx = Some(answer(OFFLINE));
        h.state_mut().poll_update();
        assert!(
            h.state().memory.off,
            "the later save dropped the unsaved opt-out"
        );
        assert!(
            update::read(&path).unwrap().off,
            "the opt-out was never saved"
        );
        assert!(
            h.state().memory_warning.is_none(),
            "the warning outlived the save"
        );
        cleanup(&path);
    }

    /// Negative control: a failed opt-out is also kept through a dismissal, so the
    /// fix does not only cover one kind of later change.
    #[test]
    fn a_failed_opt_out_survives_a_later_dismissal() {
        let path = memory_in_a_fresh_folder("pending-dismiss");
        let conflict = path.with_file_name(format!("update.{}.tmp", std::process::id()));
        std::fs::create_dir(&conflict).unwrap();
        let mut h =
            Harness::new_ui_state(|ui, app: &mut App| app.show(ui), app(Some(path.clone())));
        h.state_mut().show_settings = true;
        h.run();
        h.get_by_role_and_label(Role::CheckBox, "Check for updates when the window opens")
            .click();
        h.run();
        std::fs::remove_dir(&conflict).unwrap();
        h.state_mut().update = match update::parse(AVAILABLE) {
            Some(update::Answer::Newer(r)) => Some(r),
            _ => panic!("the fixture is not a newer release"),
        };
        h.state_mut().dismiss_update();
        let disk = update::read(&path).unwrap();
        assert!(disk.off, "the dismissal dropped the unsaved opt-out");
        assert_eq!(disk.dismissed.as_deref(), Some("v2.3.0"));
        cleanup(&path);
    }

    /// Negative control: a later explicit choice to turn checks back on wins over
    /// the failed opt-out. The pending choice is the latest one, not a sticky one.
    #[test]
    fn a_later_choice_to_turn_checks_back_on_wins_over_a_failed_opt_out() {
        let path = memory_in_a_fresh_folder("pending-on");
        let conflict = path.with_file_name(format!("update.{}.tmp", std::process::id()));
        std::fs::create_dir(&conflict).unwrap();
        let mut h =
            Harness::new_ui_state(|ui, app: &mut App| app.show(ui), app(Some(path.clone())));
        h.state_mut().show_settings = true;
        h.run();
        h.get_by_role_and_label(Role::CheckBox, "Check for updates when the window opens")
            .click();
        h.run();
        std::fs::remove_dir(&conflict).unwrap();
        h.get_by_role_and_label(Role::CheckBox, "Check for updates when the window opens")
            .click();
        h.run();
        assert!(
            !h.state().memory.off,
            "the later choice to turn checks on was not shown"
        );
        assert!(
            !update::read(&path).unwrap().off,
            "the later choice was not saved"
        );
        cleanup(&path);
    }

    #[test]
    fn the_setting_turns_the_launch_check_off_across_a_restart() {
        let path = memory_in_a_fresh_folder("setting");
        let mut h =
            Harness::new_ui_state(|ui, app: &mut App| app.show(ui), app(Some(path.clone())));
        h.state_mut().show_settings = true;
        h.run();
        h.get_by_role_and_label(Role::CheckBox, "Check for updates when the window opens")
            .click();
        h.run();
        assert!(h.state().memory.off, "the setting did not turn checks off");
        assert!(update::load(&path).off, "the setting was not saved");
        let next = App::new(
            egui::Context::default(),
            Startup {
                netdoc: Some(PathBuf::from("/nonexistent/netdoc-for-a-test")),
                update_check: true,
                update_memory: Some(path.clone()),
                ..Startup::default()
            },
        );
        assert!(
            next.update_rx.is_none(),
            "the launch check ran after the user turned it off"
        );
        cleanup(&path);
    }

    #[test]
    fn the_banner_names_its_buttons_and_dismiss_hides_it() {
        let mut h = Harness::new_ui_state(|ui, app: &mut App| app.show(ui), app(None));
        h.state_mut().update = match update::parse(AVAILABLE) {
            Some(update::Answer::Newer(r)) => Some(r),
            _ => panic!("the fixture is not a newer release"),
        };
        h.run();
        h.get_by_role_and_label(Role::Button, "Open release page");
        h.get_by_role_and_label(Role::Button, "Dismiss").click();
        h.run();
        assert!(
            h.state().update.is_none(),
            "Dismiss did not hide the banner"
        );
    }
}
