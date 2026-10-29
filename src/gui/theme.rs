//! Colors, fonts and small custom widgets for the minimalist dark UI.

use crate::engine::Verdict;
use eframe::egui::{
    self, Align2, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Frame, Margin, Pos2, Rect, Response,
    RichText, Sense, Shape, Stroke, TextStyle, Ui, Vec2, pos2, vec2,
};
use std::sync::Arc;

pub const BG: Color32 = Color32::from_rgb(0x0E, 0x10, 0x14);
pub const SIDEBAR: Color32 = Color32::from_rgb(0x12, 0x15, 0x1A);
pub const CARD: Color32 = Color32::from_rgb(0x17, 0x1B, 0x21);
pub const CARD_HOVER: Color32 = Color32::from_rgb(0x1D, 0x22, 0x2A);
pub const BORDER: Color32 = Color32::from_rgb(0x25, 0x2A, 0x33);
pub const TEXT: Color32 = Color32::from_rgb(0xE6, 0xE8, 0xEB);
pub const DIM: Color32 = Color32::from_rgb(0x8A, 0x91, 0x9C);
pub const FAINT: Color32 = Color32::from_rgb(0x5C, 0x63, 0x6E);
pub const ACCENT: Color32 = Color32::from_rgb(0x4A, 0xE3, 0xA5);
pub const ACCENT_DARK: Color32 = Color32::from_rgb(0x1F, 0xA8, 0x8A);
pub const WARN: Color32 = Color32::from_rgb(0xF5, 0xB7, 0x48);
pub const DANGER: Color32 = Color32::from_rgb(0xFF, 0x5C, 0x6C);
pub const GRAY: Color32 = Color32::from_rgb(0x9A, 0xA0, 0xAA);

pub fn semibold() -> FontFamily {
    FontFamily::Name("semibold".into())
}

pub fn install(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let load = |file: &str| std::fs::read(format!(r"C:\Windows\Fonts\{file}")).ok();
    let mut semibold_stack = Vec::new();
    if let Some(regular) = load("segoeui.ttf") {
        fonts.font_data.insert("segoe".into(), Arc::new(FontData::from_owned(regular)));
        fonts.families.entry(FontFamily::Proportional).or_default().insert(0, "segoe".into());
        semibold_stack.push("segoe".to_string());
    }
    if let Some(bold) = load("seguisb.ttf") {
        fonts.font_data.insert("segoe_sb".into(), Arc::new(FontData::from_owned(bold)));
        semibold_stack.insert(0, "segoe_sb".to_string());
    }
    semibold_stack.extend(fonts.families.get(&FontFamily::Proportional).cloned().unwrap_or_default());
    fonts.families.insert(semibold(), semibold_stack);
    ctx.set_fonts(fonts);

    ctx.all_styles_mut(|style| {
        style.text_styles = [
            (TextStyle::Small, FontId::proportional(12.0)),
            (TextStyle::Body, FontId::proportional(14.0)),
            (TextStyle::Button, FontId::proportional(14.0)),
            (TextStyle::Heading, FontId::new(24.0, semibold())),
            (TextStyle::Monospace, FontId::monospace(12.5)),
        ]
        .into();
        style.spacing.item_spacing = vec2(8.0, 8.0);
        style.spacing.button_padding = vec2(14.0, 7.0);
        style.spacing.interact_size.y = 30.0;

        let v = &mut style.visuals;
        *v = egui::Visuals::dark();
        v.panel_fill = BG;
        v.window_fill = CARD;
        v.extreme_bg_color = Color32::from_rgb(0x0B, 0x0D, 0x10);
        v.faint_bg_color = CARD;
        v.override_text_color = Some(TEXT);
        v.hyperlink_color = ACCENT;
        v.selection.bg_fill = ACCENT_DARK.gamma_multiply(0.6);
        v.selection.stroke = Stroke::new(1.0, ACCENT);
        v.window_corner_radius = CornerRadius::same(12);
        v.window_stroke = Stroke::new(1.0, BORDER);
        v.menu_corner_radius = CornerRadius::same(8);

        let r = CornerRadius::same(8);
        let w = &mut v.widgets;
        w.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
        w.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
        w.inactive.weak_bg_fill = CARD_HOVER;
        w.inactive.bg_fill = CARD_HOVER;
        w.inactive.bg_stroke = Stroke::new(1.0, BORDER);
        w.inactive.fg_stroke = Stroke::new(1.0, TEXT);
        w.hovered.weak_bg_fill = Color32::from_rgb(0x25, 0x2B, 0x35);
        w.hovered.bg_fill = Color32::from_rgb(0x25, 0x2B, 0x35);
        w.hovered.bg_stroke = Stroke::new(1.0, Color32::from_rgb(0x34, 0x3B, 0x47));
        w.hovered.fg_stroke = Stroke::new(1.0, TEXT);
        w.active.weak_bg_fill = Color32::from_rgb(0x2C, 0x33, 0x3E);
        w.active.bg_fill = Color32::from_rgb(0x2C, 0x33, 0x3E);
        w.active.fg_stroke = Stroke::new(1.0, TEXT);
        for wv in [&mut w.noninteractive, &mut w.inactive, &mut w.hovered, &mut w.active, &mut w.open] {
            wv.corner_radius = r;
            wv.expansion = 0.0;
        }
    });
}

pub fn card() -> Frame {
    Frame::new().fill(CARD).corner_radius(CornerRadius::same(12)).stroke(Stroke::new(1.0, BORDER)).inner_margin(Margin::same(18))
}

pub fn verdict_color(v: Verdict) -> Color32 {
    match v {
        Verdict::Clean => ACCENT,
        Verdict::Suspicious => WARN,
        Verdict::Malicious => DANGER,
    }
}

pub fn title(ui: &mut Ui, text: &str, subtitle: &str) {
    ui.label(RichText::new(text).size(26.0).family(semibold()));
    if !subtitle.is_empty() {
        ui.label(RichText::new(subtitle).color(DIM));
    }
    ui.add_space(14.0);
}

pub fn section_label(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text.to_uppercase()).size(11.5).color(FAINT).family(semibold()));
}

/// Small rounded pill, e.g. a verdict badge.
pub fn chip(ui: &mut Ui, text: &str, color: Color32) -> Response {
    let font = FontId::new(11.5, semibold());
    let galley = ui.painter().layout_no_wrap(text.to_string(), font, color);
    let size = galley.size() + vec2(16.0, 6.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::hover());
    ui.painter().rect_filled(rect, CornerRadius::same((size.y / 2.0) as u8), color.gamma_multiply(0.16));
    ui.painter().galley(rect.center() - galley.size() / 2.0, galley, color);
    resp
}

pub fn primary_button(ui: &mut Ui, text: &str) -> Response {
    ui.add(
        egui::Button::new(RichText::new(text).color(Color32::from_rgb(0x06, 0x1A, 0x12)).family(semibold()))
            .fill(ACCENT)
            .stroke(Stroke::NONE)
            .corner_radius(CornerRadius::same(8)),
    )
}

pub fn button(ui: &mut Ui, text: &str) -> Response {
    ui.add(egui::Button::new(text).corner_radius(CornerRadius::same(8)))
}

pub fn danger_button(ui: &mut Ui, text: &str) -> Response {
    ui.add(
        egui::Button::new(RichText::new(text).color(DANGER))
            .fill(DANGER.gamma_multiply(0.12))
            .stroke(Stroke::new(1.0, DANGER.gamma_multiply(0.4)))
            .corner_radius(CornerRadius::same(8)),
    )
}

fn lerp_color(a: Color32, b: Color32, t: f32) -> Color32 {
    let l = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t) as u8;
    Color32::from_rgb(l(a.r(), b.r()), l(a.g(), b.g()), l(a.b(), b.b()))
}

/// iOS-style switch.
pub fn toggle(ui: &mut Ui, on: &mut bool) -> Response {
    let (rect, mut resp) = ui.allocate_exact_size(vec2(40.0, 22.0), Sense::click());
    if resp.clicked() {
        *on = !*on;
        resp.mark_changed();
    }
    let t = ui.ctx().animate_bool_with_time(resp.id, *on, 0.12);
    let radius = rect.height() / 2.0;
    let track = lerp_color(BORDER, ACCENT, t);
    ui.painter().rect_filled(rect, CornerRadius::same(radius as u8), track);
    let x = rect.left() + radius + t * (rect.width() - 2.0 * radius);
    let knob = lerp_color(GRAY, Color32::from_rgb(0x06, 0x1A, 0x12), t);
    ui.painter().circle_filled(pos2(x, rect.center().y), radius - 4.0, knob);
    resp
}

/// Setting row: title + description on the left, a switch on the right.
pub fn toggle_row(ui: &mut Ui, title: &str, desc: &str, value: &mut bool) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.set_max_width(ui.available_width() - 60.0);
            ui.label(RichText::new(title).family(semibold()));
            if !desc.is_empty() {
                ui.label(RichText::new(desc).color(DIM).size(12.5));
            }
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            changed = toggle(ui, value).changed();
        });
    });
    changed
}

pub fn nav_item(ui: &mut Ui, label: &str, selected: bool, badge: Option<usize>) -> bool {
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 38.0), Sense::click());
    let p = ui.painter();
    if selected {
        p.rect_filled(rect, CornerRadius::same(8), CARD_HOVER);
        p.rect_filled(Rect::from_min_size(rect.left_top() + vec2(0.0, 11.0), vec2(3.0, 16.0)), CornerRadius::same(2), ACCENT);
    } else if resp.hovered() {
        p.rect_filled(rect, CornerRadius::same(8), CARD);
    }
    let color = if selected { TEXT } else { DIM };
    let font = FontId::new(14.5, if selected { semibold() } else { FontFamily::Proportional });
    p.text(rect.left_center() + vec2(16.0, 0.0), Align2::LEFT_CENTER, label, font, color);
    if let Some(n) = badge.filter(|&n| n > 0) {
        let c = rect.right_center() - vec2(18.0, 0.0);
        p.circle_filled(c, 9.0, DANGER.gamma_multiply(0.2));
        p.text(c, Align2::CENTER_CENTER, n.min(99).to_string(), FontId::new(11.0, semibold()), DANGER);
    }
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp.clicked()
}

/// Vector version of the app icon.
pub fn paint_shield(ui: &Ui, center: Pos2, height: f32, color: Color32, check: bool) {
    let h = height;
    let w = h * 0.76;
    let top = center.y - h / 2.0;
    let mid = top + h * 0.48;
    let bottom = center.y + h / 2.0;
    let r = h * 0.12;
    let left = center.x - w / 2.0;
    let right = center.x + w / 2.0;

    let mut pts = Vec::new();
    for i in 0..=8 {
        let a = std::f32::consts::PI + std::f32::consts::FRAC_PI_2 * i as f32 / 8.0;
        pts.push(pos2(left + r + r * a.cos(), top + r + r * a.sin()));
    }
    for i in 0..=8 {
        let a = -std::f32::consts::FRAC_PI_2 + std::f32::consts::FRAC_PI_2 * i as f32 / 8.0;
        pts.push(pos2(right - r + r * a.cos(), top + r + r * a.sin()));
    }
    for i in 0..=16 {
        let t = i as f32 / 16.0;
        pts.push(pos2(center.x + (w / 2.0) * (1.0 - t * t), mid + t * (bottom - mid)));
    }
    for i in (0..16).rev() {
        let t = i as f32 / 16.0;
        pts.push(pos2(center.x - (w / 2.0) * (1.0 - t * t), mid + t * (bottom - mid)));
    }
    ui.painter().add(Shape::convex_polygon(pts, color, Stroke::NONE));

    let s = |x: f32, y: f32| pos2(center.x + (x - 0.5) * h, top + y * h);
    let stroke = Stroke::new(h * 0.085, BG);
    if check {
        ui.painter().add(Shape::line(vec![s(0.33, 0.47), s(0.45, 0.60), s(0.67, 0.34)], stroke));
    } else {
        ui.painter().line_segment([s(0.5, 0.28), s(0.5, 0.52)], stroke);
        ui.painter().circle_filled(s(0.5, 0.66), h * 0.05, BG);
    }
}

pub fn shield_size(ui: &mut Ui, size: f32) -> Rect {
    ui.allocate_exact_size(Vec2::splat(size), Sense::hover()).0
}
