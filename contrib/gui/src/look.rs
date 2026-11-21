#![allow(dead_code)]
//! Theme and custom widgets, in the style of the net-watch app.
use eframe::egui::{
    self, Color32, CornerRadius, FontId, Rect, Response, Sense, Stroke, pos2, vec2,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// The colors a theme changes.
pub struct Palette {
    pub bg: Color32,
    pub body: Color32,
    pub key: Color32,
    pub key_hover: Color32,
    pub accent: Color32,
    pub accent_soft: Color32,
    pub text: Color32,
    pub weak: Color32,
    /// Good, worrying and bad news.
    pub good: Color32,
    pub warn: Color32,
    pub bad: Color32,
    /// The second line on a graph: upload speed.
    pub second: Color32,
    /// The edge of a card.
    pub edge: Color32,
    /// Dark text on a light background.
    pub light: bool,
}

const fn rgb(hex: u32) -> Color32 {
    Color32::from_rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

/// A dark theme with cards that have no edges.
const fn palette(c: [u32; 8]) -> Palette {
    Palette {
        bg: rgb(c[0]),
        body: rgb(c[1]),
        key: rgb(c[2]),
        key_hover: rgb(c[3]),
        accent: rgb(c[4]),
        accent_soft: rgb(c[5]),
        text: rgb(c[6]),
        weak: rgb(c[7]),
        good: rgb(0x4cd98a),
        warn: rgb(0xffb454),
        bad: rgb(0xff5c6c),
        second: rgb(0x4fb3ff),
        edge: rgb(c[1]),
        light: false,
    }
}

/// Themes by name, the first is the default.
pub const THEMES: [(&str, Palette); 8] = [
    (
        "Clean light",
        Palette {
            bg: rgb(0xf1f4f9),
            body: rgb(0xffffff),
            key: rgb(0xe7ebf1),
            key_hover: rgb(0xdbe2eb),
            accent: rgb(0x2563eb),
            accent_soft: rgb(0xd5e1fc),
            text: rgb(0x0f172a),
            weak: rgb(0x475569),
            good: rgb(0x047857),
            warn: rgb(0xb45309),
            bad: rgb(0xe11d48),
            second: rgb(0x059669),
            edge: rgb(0xe2e7ee),
            light: true,
        },
    ),
    (
        "Mica dark",
        Palette {
            bg: rgb(0x161a23),
            body: rgb(0x232836),
            key: rgb(0x2c3242),
            key_hover: rgb(0x363d50),
            accent: rgb(0x3b82f6),
            accent_soft: rgb(0x1d3a6b),
            text: rgb(0xf1f5f9),
            weak: rgb(0x94a3b8),
            good: rgb(0x34d399),
            warn: rgb(0xfbbf24),
            bad: rgb(0xfb7185),
            second: rgb(0x34d399),
            edge: rgb(0x30374a),
            light: false,
        },
    ),
    (
        "Violet",
        palette([
            0x0f0d16, 0x1b1726, 0x2a243a, 0x372f4b, 0x7c4dff, 0x4a338f, 0xece8f5, 0x9a93ad,
        ]),
    ),
    (
        "Ocean",
        palette([
            0x0b1118, 0x14202c, 0x1f3142, 0x2a4157, 0x2f8fff, 0x1f538a, 0xe6f1fa, 0x8fa3b5,
        ]),
    ),
    (
        "Forest",
        palette([
            0x0c130f, 0x15211a, 0x213327, 0x2c4434, 0x22a95e, 0x1b6a40, 0xe6f4ea, 0x8ea89a,
        ]),
    ),
    (
        "Sunset",
        palette([
            0x15100c, 0x241a14, 0x36281e, 0x473428, 0xf2672a, 0x8f4223, 0xf7ece4, 0xb09d90,
        ]),
    ),
    (
        "Rose",
        palette([
            0x150c11, 0x24151d, 0x37212c, 0x482c3a, 0xf0407e, 0x8f2c4c, 0xf8e8ef, 0xb294a3,
        ]),
    ),
    (
        "Graphite",
        palette([
            0x101112, 0x1b1c1f, 0x2a2b2f, 0x37393e, 0x5f6b7a, 0x3f4651, 0xeceef1, 0x989ca4,
        ]),
    ),
];

static THEME: AtomicUsize = AtomicUsize::new(0);
static ANIMATE: AtomicBool = AtomicBool::new(true);

pub fn pal() -> &'static Palette {
    &THEMES[THEME.load(Ordering::Relaxed)].1
}

/// Switch to theme `index` (out of range keeps the current one).
pub fn set_theme(ctx: &egui::Context, index: usize) {
    if index < THEMES.len() {
        THEME.store(index, Ordering::Relaxed);
        install(ctx);
    }
}

pub fn animated() -> bool {
    ANIMATE.load(Ordering::Relaxed)
}

pub fn set_animated(on: bool) {
    ANIMATE.store(on, Ordering::Relaxed);
}

/// 0 to 1 as `on` turns true, eased over `secs`; instant with animations off.
fn ease(ctx: &egui::Context, id: egui::Id, on: bool, secs: f32) -> f32 {
    if animated() {
        ctx.animate_bool_with_time_and_easing(id, on, secs, egui::emath::easing::cubic_out)
    } else {
        on as u8 as f32
    }
}

const PULSE_SECS: f64 = 0.45;

/// How far through its click pulse the widget `id` is, if it's in one.
/// `clicked` starts a new pulse.
fn pulse(ctx: &egui::Context, id: egui::Id, clicked: bool) -> Option<f32> {
    if !animated() {
        return None;
    }
    let id = id.with("pulse");
    let now = ctx.input(|i| i.time);
    if clicked {
        ctx.data_mut(|d| d.insert_temp(id, now));
    }
    let t = (now - ctx.data(|d| d.get_temp::<f64>(id))?) / PULSE_SECS;
    if t >= 1.0 {
        return None;
    }
    ctx.request_repaint();
    Some(t as f32)
}

/// An accent ring spreading out from `rect` and fading.
fn paint_pulse(p: &egui::Painter, rect: Rect, radius: f32, t: f32) {
    let k = egui::emath::easing::cubic_out(t);
    let grow = 9.0 * k;
    let color = pal().accent.gamma_multiply(0.75 * (1.0 - k));
    p.rect_stroke(
        rect.expand(grow),
        radius + grow,
        Stroke::new(2.5 * (1.0 - k) + 0.5, color),
        egui::StrokeKind::Outside,
    );
}

pub fn good() -> Color32 {
    pal().good
}

pub fn warn() -> Color32 {
    pal().warn
}

pub fn bad() -> Color32 {
    pal().bad
}

pub fn install(ctx: &egui::Context) {
    let theme = if pal().light {
        egui::Theme::Light
    } else {
        egui::Theme::Dark
    };
    ctx.set_theme(theme);
    ctx.style_mut_of(theme, |style| {
        use egui::TextStyle as T;
        style
            .text_styles
            .insert(T::Body, FontId::proportional(15.0));
        style
            .text_styles
            .insert(T::Button, FontId::proportional(15.0));
        style
            .text_styles
            .insert(T::Heading, FontId::proportional(21.0));
        style
            .text_styles
            .insert(T::Small, FontId::proportional(12.5));
        style.spacing.item_spacing = vec2(10.0, 10.0);
        style.spacing.button_padding = vec2(12.0, 7.0);
        style.spacing.interact_size.y = 34.0;

        let v = &mut style.visuals;
        v.panel_fill = pal().bg;
        v.hyperlink_color = pal().accent;
        if pal().light {
            v.faint_bg_color = pal().bg;
        }
        v.window_fill = pal().body;
        v.extreme_bg_color = pal().key;
        v.override_text_color = Some(pal().text);
        v.selection.bg_fill = pal().accent_soft;
        v.selection.stroke = Stroke::new(1.0, pal().accent);
        v.window_corner_radius = CornerRadius::same(14);
        v.menu_corner_radius = CornerRadius::same(12);
        v.window_stroke = Stroke::new(1.0, pal().key_hover);
        for (w, fill) in [
            (&mut v.widgets.noninteractive, pal().body),
            (&mut v.widgets.inactive, pal().key),
            (&mut v.widgets.hovered, pal().key_hover),
            (&mut v.widgets.active, pal().accent),
            (&mut v.widgets.open, pal().key_hover),
        ] {
            w.bg_fill = fill;
            w.weak_bg_fill = fill;
            w.corner_radius = CornerRadius::same(10);
            w.bg_stroke = Stroke::NONE;
            w.expansion = 0.0;
        }
        v.widgets.noninteractive.fg_stroke.color = pal().weak;
        v.widgets.inactive.fg_stroke.color = pal().text;
        v.widgets.hovered.fg_stroke.color = pal().text;
        // Also the color of strong text, so dark on a light theme.
        v.widgets.active.fg_stroke.color = if pal().light {
            pal().text
        } else {
            Color32::WHITE
        };
        v.widgets.hovered.bg_stroke = Stroke::new(1.0, pal().accent_soft);
    });
}

/// An on/off switch whose knob slides across.
pub fn toggle(ui: &mut egui::Ui, label: &str, on: &mut bool) -> Response {
    let size = vec2(44.0, 24.0);
    let (rect, mut resp) = ui.allocate_exact_size(size, Sense::click());
    if resp.clicked() {
        *on = !*on;
        resp.mark_changed();
    }
    resp.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::Checkbox, ui.is_enabled(), *on, label)
    });
    if ui.is_rect_visible(rect) {
        let t = ease(ui.ctx(), resp.id, *on, 0.18);
        let r = size.y / 2.0;
        let track = pal().key_hover.lerp_to_gamma(pal().accent, t);
        let p = ui.painter();
        p.rect_filled(rect, r, track);
        let x = egui::lerp(rect.left() + r..=rect.right() - r, t);
        let knob = if resp.hovered() { r - 2.0 } else { r - 3.0 };
        p.circle_filled(
            pos2(x, rect.center().y + 1.0),
            knob,
            Color32::from_black_alpha(60),
        );
        p.circle_filled(pos2(x, rect.center().y), knob, Color32::WHITE);
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// A round sample of a theme: its key color ringed by its accent, with a
/// ring around it when it's the current one.
pub fn swatch(ui: &mut egui::Ui, theme: &Palette, selected: bool) -> Response {
    let d = 34.0;
    let (rect, resp) = ui.allocate_exact_size(vec2(d, d), Sense::click());
    if ui.is_rect_visible(rect) {
        let ctx = ui.ctx();
        let sel = ease(ctx, resp.id.with("sel"), selected, 0.2);
        let hover = ease(ctx, resp.id.with("hover"), resp.hovered(), 0.15);
        let c = rect.center();
        let r = d / 2.0 - 4.0 + 1.5 * hover;
        let p = ui.painter();
        p.circle_filled(c, r, theme.accent);
        p.circle_filled(c + vec2(r * 0.25, r * 0.25), r * 0.45, theme.key);
        if sel > 0.0 {
            p.circle_stroke(c, r + 3.0, Stroke::new(2.0, pal().text.gamma_multiply(sel)));
        }
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// A rounded button that brightens on hover and ripples when clicked;
/// `primary` ones are filled with the accent.
pub fn button(ui: &mut egui::Ui, text: &str, primary: bool, enabled: bool) -> Response {
    let font = egui::TextStyle::Button.resolve(ui.style());
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_string(), font.clone(), pal().text);
    let size = vec2(galley.size().x + 28.0, galley.size().y.max(20.0) + 14.0);
    let (rect, resp) = ui.allocate_exact_size(
        size,
        if enabled {
            Sense::click()
        } else {
            Sense::hover()
        },
    );
    resp.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, enabled, text));
    if ui.is_rect_visible(rect) {
        let hover = ease(
            ui.ctx(),
            resp.id.with("hover"),
            enabled && resp.hovered(),
            0.15,
        );
        let (base, lit) = if primary {
            (
                pal().accent,
                pal().accent.lerp_to_gamma(Color32::WHITE, 0.15),
            )
        } else {
            (pal().key, pal().key_hover)
        };
        let mut fill = base.lerp_to_gamma(lit, hover);
        let mut text_color = if primary { Color32::WHITE } else { pal().text };
        if !enabled {
            fill = fill.gamma_multiply(0.55);
            text_color = text_color.gamma_multiply(0.5);
        }
        let press = if resp.is_pointer_button_down_on() {
            1.0
        } else {
            0.0
        };
        let r = rect.shrink(press);
        let p = ui.painter();
        p.rect_filled(r, 10.0, fill);
        // Laid out again in its own color: white on the accent, on any theme.
        let galley = ui
            .painter()
            .layout_no_wrap(text.to_string(), font, text_color);
        p.galley(r.center() - galley.size() / 2.0, galley, text_color);
        if let Some(t) = pulse(ui.ctx(), resp.id, resp.clicked()) {
            paint_pulse(p, rect, 10.0, t);
        }
    }
    if enabled {
        resp.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        resp
    }
}

/// A row of choices with the chosen one highlighted; the highlight slides
/// to a new choice. True when the choice changed.
pub fn tabs(ui: &mut egui::Ui, id: &str, chosen: &mut usize, labels: &[&str]) -> bool {
    let font = egui::TextStyle::Small.resolve(ui.style());
    let widths: Vec<f32> = labels
        .iter()
        .map(|l| {
            ui.painter()
                .layout_no_wrap(l.to_string(), font.clone(), pal().text)
                .size()
                .x
                + 22.0
        })
        .collect();
    let size = vec2(widths.iter().sum::<f32>() + 6.0, 30.0);
    let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
    let p = ui.painter().clone();
    p.rect_filled(rect, 10.0, pal().key);
    let mut x = rect.left() + 3.0;
    let mut rects = Vec::new();
    for w in &widths {
        rects.push(Rect::from_min_size(
            pos2(x, rect.top() + 3.0),
            vec2(*w, size.y - 6.0),
        ));
        x += w;
    }
    let mut changed = false;
    for (i, r) in rects.iter().enumerate() {
        let resp = ui
            .interact(*r, ui.id().with(id).with(i), Sense::click())
            .on_hover_cursor(egui::CursorIcon::PointingHand);
        resp.widget_info(|| {
            egui::WidgetInfo::selected(egui::WidgetType::RadioButton, true, i == *chosen, labels[i])
        });
        if resp.clicked() && *chosen != i {
            *chosen = i;
            changed = true;
        }
    }
    let target = rects[(*chosen).min(rects.len() - 1)];
    let anim = |v: f32, k: &str| {
        if animated() {
            ui.ctx()
                .animate_value_with_time(ui.id().with(id).with(k), v, 0.2)
        } else {
            v
        }
    };
    let (l, w) = (anim(target.left(), "l"), anim(target.width(), "w"));
    p.rect_filled(
        Rect::from_min_size(pos2(l, target.top()), vec2(w, target.height())),
        8.0,
        pal().accent_soft,
    );
    for (i, r) in rects.iter().enumerate() {
        let color = if i == *chosen { pal().text } else { pal().weak };
        p.text(
            r.center(),
            egui::Align2::CENTER_CENTER,
            labels[i],
            font.clone(),
            color,
        );
    }
    changed
}

/// A rounded panel in the body color.
pub fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::new()
        .fill(pal().body)
        .stroke(Stroke::new(1.0, pal().edge))
        .shadow(shadow(0.0))
        .corner_radius(12)
        .inner_margin(egui::Margin::symmetric(16, 14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// A soft shadow under cards on light themes, deeper as `lift` goes to 1.
fn shadow(lift: f32) -> egui::Shadow {
    if !pal().light {
        return egui::Shadow::NONE;
    }
    egui::Shadow {
        offset: [0, (2.0 + 6.0 * lift) as i8],
        blur: (8.0 + 16.0 * lift) as u8,
        spread: 0,
        color: Color32::from_black_alpha((10.0 + 18.0 * lift) as u8),
    }
}

/// A card that opens something when clicked; on hover its edge takes the
/// accent and it lifts.
pub fn tile(ui: &mut egui::Ui, label: &str, add: impl FnOnce(&mut egui::Ui)) -> Response {
    let id = ui.id().with(label);
    // Whether it was hovered last frame, so the card is drawn to match.
    let hovered = ui.ctx().read_response(id).is_some_and(|r| r.hovered());
    let t = ease(ui.ctx(), id.with("hover"), hovered, 0.18);
    // Drawn a little higher as it lifts; where it takes the pointer stays put.
    let lift = egui::emath::TSTransform::from_translation(vec2(0.0, -3.0 * t));
    let rect = ui
        .with_visual_transform(lift, |ui| {
            egui::Frame::new()
                .fill(pal().body)
                .stroke(Stroke::new(
                    1.0,
                    pal().edge.lerp_to_gamma(pal().accent, 0.55 * t),
                ))
                .shadow(shadow(t))
                .corner_radius(16)
                .inner_margin(egui::Margin::same(18))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    // Left-aligned: in a justified layout wrapped text spreads out.
                    ui.with_layout(egui::Layout::top_down(egui::Align::Min), add)
                })
                .response
                .rect
        })
        .inner;
    let resp = ui.interact(rect, id, Sense::click());
    resp.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, label));
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// A small button in a tint of the accent, like "Check now". With
/// `clickable` false it's only drawn, for something on top to take the
/// click.
pub fn chip(ui: &mut egui::Ui, text: &str, enabled: bool, clickable: bool) -> Response {
    let color = if enabled { pal().accent } else { pal().weak };
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_string(), FontId::proportional(12.5), color);
    let size = galley.size() + vec2(18.0, 8.0);
    let (rect, resp) = ui.allocate_exact_size(
        size,
        if enabled && clickable {
            Sense::click()
        } else {
            Sense::hover()
        },
    );
    resp.widget_info(|| {
        egui::WidgetInfo::labeled(egui::WidgetType::Button, enabled && clickable, text)
    });
    let hover = enabled && ui.rect_contains_pointer(rect);
    let p = ui.painter();
    p.rect_filled(
        rect,
        7.0,
        color.gamma_multiply(if hover { 0.24 } else { 0.12 }),
    );
    p.galley(rect.center() - galley.size() / 2.0, galley, color);
    if enabled {
        resp.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        resp
    }
}

/// How far a card has come in, 0 to 1, set by Home as it draws each card
/// so the card's bars can grow with it.
pub fn appear(ctx: &egui::Context) -> f32 {
    ctx.data(|d| d.get_temp(egui::Id::new("appear")))
        .unwrap_or(1.0)
}

pub fn set_appear(ctx: &egui::Context, t: f32) {
    ctx.data_mut(|d| d.insert_temp(egui::Id::new("appear"), t));
}

/// 0 to 1 over `secs` from `since` (the input clock), eased; 1 with
/// animations off. Keeps the frames coming until it's done.
pub fn progress(ctx: &egui::Context, since: f64, secs: f64) -> f32 {
    if !animated() {
        return 1.0;
    }
    let t = ((ctx.input(|i| i.time) - since) / secs).clamp(0.0, 1.0) as f32;
    if t < 1.0 {
        ctx.request_repaint();
    }
    egui::emath::easing::cubic_out(t)
}

/// When `key` last changed for `id` (the input clock); far in the past
/// until it first changes, so nothing plays when a window opens.
pub fn changed_at(ctx: &egui::Context, id: egui::Id, key: u64) -> f64 {
    let now = ctx.input(|i| i.time);
    ctx.data_mut(|d| {
        let slot = d.get_temp_mut_or_insert_with(id, || (key, f64::NEG_INFINITY));
        if slot.0 != key {
            *slot = (key, now);
        }
        slot.1
    })
}

/// 0 to 1 (not eased) over `secs` from `since` while that's under way;
/// `None` once it's done or with animations off.
pub fn playing(ctx: &egui::Context, since: f64, secs: f64) -> Option<f32> {
    if !animated() {
        return None;
    }
    let t = (ctx.input(|i| i.time) - since) / secs;
    if !(0.0..1.0).contains(&t) {
        return None;
    }
    ctx.request_repaint();
    Some(t as f32)
}

/// A value that glides to `to` instead of jumping; `to` with animations off.
pub fn glide(ctx: &egui::Context, id: egui::Id, to: f32, secs: f32) -> f32 {
    if animated() {
        ctx.animate_value_with_time(id, to, secs)
    } else {
        to
    }
}

/// A line of detail for what the pointer is over inside a card, shown as
/// the card's tooltip (the card is on top, so the parts can't show one).
pub fn set_tip(ctx: &egui::Context, text: String) {
    ctx.data_mut(|d| d.insert_temp(egui::Id::new("tip"), text));
}

pub fn take_tip(ctx: &egui::Context) -> Option<String> {
    ctx.data_mut(|d| d.remove_temp::<String>(egui::Id::new("tip")))
}

/// A small uppercase heading, like the cards' titles.
pub fn caption(text: &str) -> egui::RichText {
    egui::RichText::new(text.to_uppercase())
        .small()
        .color(pal().weak)
        .extra_letter_spacing(0.8)
}
