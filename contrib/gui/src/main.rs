// No console window behind the app on Windows.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod look;
mod report;
mod runner;

use eframe::egui::{self, Color32, RichText, vec2};
use look::{bad, good, pal, warn};
use report::{Outcome, Report, Tone};
use runner::{Handle, Msg};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc::{Receiver, TryRecvError, channel};
use std::time::Instant;

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
    ctx: egui::Context,
    /// NETDOC_GUI_SCREENSHOT=file.ppm: save the window, then quit.
    screenshot: Option<(String, u32)>,
}

impl App {
    fn new(ctx: egui::Context) -> Self {
        let theme = load_theme();
        look::set_theme(&ctx, theme);
        look::install(&ctx);
        let netdoc = runner::find_netdoc();
        let version_rx = netdoc.clone().map(runner::start_version);
        let target = std::env::var("NETDOC_GUI_TARGET").unwrap_or_default();
        let mode = std::env::var("NETDOC_GUI_MODE")
            .ok()
            .and_then(|m| m.parse().ok())
            .filter(|m| *m < MODES.len());
        let mut app = App {
            netdoc,
            netdoc_version: None,
            version_rx,
            profile: std::env::var("NETDOC_GUI_PROFILE")
                .ok()
                .and_then(|p| PROFILES.iter().position(|x| x.0 == p))
                .unwrap_or(0),
            part: None,
            why: std::env::var_os("NETDOC_GUI_WHY").is_some(),
            mode: mode.unwrap_or(if target.is_empty() { 0 } else { 1 }),
            target,
            watch: std::env::var_os("NETDOC_GUI_WATCH").is_some(),
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
            ctx,
            screenshot: std::env::var("NETDOC_GUI_SCREENSHOT").ok().map(|p| (p, 0)),
        };
        if std::env::var_os("NETDOC_GUI_AUTORUN").is_some() {
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
                Ok(Msg::Failed(e)) => self.error = Some(e),
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
            if ui
                .interact(resp.rect, ui.id().with(("part", i)), egui::Sense::click())
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
        self.take_screenshot(ui);
        egui::Panel::top("top")
            .frame(
                egui::Frame::new()
                    .fill(pal().bg)
                    .inner_margin(egui::Margin::symmetric(16, 0)),
            )
            .show(ui, |ui| {
                self.header(ui);
            });
        egui::Panel::bottom("status").frame(egui::Frame::new().fill(pal().bg).inner_margin(egui::Margin::symmetric(16, 6))).show(ui, |ui| {
            match &self.note {
                Some((n, err)) => {
                    ui.add(egui::Label::new(RichText::new(n).small().color(if *err { bad() } else { pal().text })).wrap());
                }
                None => {
                    ui.label(weak("Results come from Network Doctor (netdoc). This window only shows them.").small());
                }
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
        Box::new(|cc| Ok(Box::new(App::new(cc.egui_ctx.clone())))),
    )
}

#[cfg(test)]
mod tests {
    use super::exit_error;

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
    use egui_kittest::kittest::Queryable;

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

    /// The stand-in netdoc's record of checks, read by the child process.
    fn stub_log() -> PathBuf {
        PathBuf::from(std::env::var_os("NETDOC").expect("run by the stub-process helper"))
            .with_file_name("invoked")
    }

    /// Whether the stand-in netdoc has been asked to run a check.
    fn checks_started() -> bool {
        stub_log().exists()
    }

    fn window() -> Harness<'static, App> {
        Harness::new_ui_state(
            |ui, app: &mut App| app.show(ui),
            App::new(egui::Context::default()),
        )
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
        let mut h = window();
        let outcome = report::parse(include_str!("../tests/fixtures/healthy.json")).unwrap();
        h.state_mut()
            .history
            .push((Instant::now(), Rc::new(outcome)));
        h.run();
        let controls = [
            (Role::Button, "Settings"),
            (Role::Button, "Export report"),
            (Role::RadioButton, "My connection"),
            (Role::RadioButton, "A website or server"),
            (Role::RadioButton, "A service"),
            (Role::CheckBox, "Keep watching"),
            (Role::Button, "Check again"),
        ];
        let mut reached = vec![false; controls.len()];
        for _ in 0..80 {
            h.key_press(egui::Key::Tab);
            h.run();
            for (i, (role, name)) in controls.iter().enumerate() {
                if h.get_by_role_and_label(*role, name).is_focused() {
                    reached[i] = true;
                }
            }
        }
        let missed: Vec<&str> = controls
            .iter()
            .zip(&reached)
            .filter(|(_, got)| !**got)
            .map(|((_, name), _)| *name)
            .collect();
        assert!(missed.is_empty(), "Tab never reached: {missed:?}");
        // Moving focus must start no diagnostic check. App::new's version probe
        // is not a check, and the stub records only checks.
        assert!(!checks_started(), "moving focus with Tab started a check");
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
