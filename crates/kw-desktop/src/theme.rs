//! Termius 风格 6 套主题色板与 egui Visuals 映射。

use eframe::egui::{self, Color32, CornerRadius, Stroke, Visuals};

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct Palette {
    pub id: &'static str,
    pub name: &'static str,
    pub dark: bool,
    pub bg: Color32,
    pub bg_elev: Color32,
    pub panel: Color32,
    pub surface2: Color32,
    pub surface3: Color32,
    pub border: Color32,
    pub text: Color32,
    pub dim: Color32,
    pub faint: Color32,
    pub accent: Color32,
    pub accent_soft: Color32,
    pub ok: Color32,
    pub ok_soft: Color32,
    pub warn: Color32,
    pub warn_soft: Color32,
    pub danger: Color32,
    pub danger_soft: Color32,
}

const fn rgb(r: u8, g: u8, b: u8) -> Color32 {
    Color32::from_rgb(r, g, b)
}

pub const PALETTES: [Palette; 2] = [
    Palette {
        id: "obsidian",
        name: "曜石",
        dark: true,
        bg: rgb(0x0B, 0x0D, 0x12),
        bg_elev: rgb(0x10, 0x14, 0x1D),
        panel: rgb(0x14, 0x19, 0x23),
        surface2: rgb(0x0E, 0x12, 0x1A),
        surface3: rgb(0x1B, 0x22, 0x30),
        border: rgb(0x21, 0x29, 0x38),
        text: rgb(0xE6, 0xED, 0xF3),
        dim: rgb(0x9A, 0xA7, 0xB6),
        faint: rgb(0x63, 0x70, 0x81),
        accent: rgb(0x3B, 0x82, 0xF6),
        accent_soft: rgb(0x15, 0x25, 0x40),
        ok: rgb(0x10, 0xB9, 0x81),
        ok_soft: rgb(0x0F, 0x29, 0x22),
        warn: rgb(0xD6, 0xA0, 0x34),
        warn_soft: rgb(0x2A, 0x24, 0x18),
        danger: rgb(0xF8, 0x51, 0x49),
        danger_soft: rgb(0x2A, 0x16, 0x18),
    },
    Palette {
        id: "linen",
        name: "亚麻",
        dark: false,
        bg: rgb(0xF6, 0xF3, 0xEC),
        bg_elev: rgb(0xFD, 0xFB, 0xF6),
        panel: rgb(0xFC, 0xF9, 0xF2),
        surface2: rgb(0xEF, 0xEB, 0xE1),
        surface3: rgb(0xE7, 0xE1, 0xD5),
        border: rgb(0xDC, 0xD5, 0xC6),
        text: rgb(0x26, 0x23, 0x1E),
        dim: rgb(0x62, 0x5B, 0x4F),
        faint: rgb(0x91, 0x89, 0x7B),
        accent: rgb(0x2B, 0x5F, 0xB8),
        accent_soft: rgb(0xE3, 0xEA, 0xF6),
        ok: rgb(0x1F, 0x7A, 0x45),
        ok_soft: rgb(0xE1, 0xF0, 0xE6),
        warn: rgb(0xA8, 0x58, 0x0C),
        warn_soft: rgb(0xF6, 0xE9, 0xD3),
        danger: rgb(0xC9, 0x34, 0x2D),
        danger_soft: rgb(0xF8, 0xE3, 0xE1),
    },
];

pub const THEME_CHOICES: [(&str, &str); 2] = [
    ("obsidian", "曜石"),
    ("linen", "亚麻"),
];

pub fn resolve_palette(choice: &str, system_dark: bool) -> Palette {
    match choice {
        "linen" => PALETTES[1],
        "obsidian" => PALETTES[0],
        _ => {
            if system_dark {
                PALETTES[0]
            } else {
                PALETTES[1]
            }
        }
    }
}

pub fn apply_palette(ctx: &egui::Context, p: &Palette) {
    let mut visuals = if p.dark {
        Visuals::dark()
    } else {
        Visuals::light()
    };
    visuals.panel_fill = p.bg;
    visuals.window_fill = p.bg_elev;
    visuals.extreme_bg_color = p.surface2;
    visuals.faint_bg_color = p.panel;
    visuals.code_bg_color = p.surface2;
    visuals.override_text_color = Some(p.text);
    visuals.window_stroke = Stroke::new(1.0_f32, p.border);
    visuals.window_corner_radius = CornerRadius::same(10);

    visuals.widgets.noninteractive.bg_fill = p.panel;
    visuals.widgets.noninteractive.weak_bg_fill = p.panel;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, p.border);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, p.text);
    visuals.widgets.noninteractive.corner_radius = CornerRadius::same(7);

    visuals.widgets.inactive.bg_fill = p.surface3;
    visuals.widgets.inactive.weak_bg_fill = p.surface3;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, p.border);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, p.text);
    visuals.widgets.inactive.corner_radius = CornerRadius::same(7);

    visuals.widgets.hovered.bg_fill = p.accent_soft;
    visuals.widgets.hovered.weak_bg_fill = p.accent_soft;
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, p.accent);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, p.text);
    visuals.widgets.hovered.corner_radius = CornerRadius::same(7);

    visuals.widgets.active.bg_fill = p.accent;
    visuals.widgets.active.weak_bg_fill = p.accent;
    visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, p.accent);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0_f32, Color32::WHITE);
    visuals.widgets.active.corner_radius = CornerRadius::same(7);

    visuals.selection.bg_fill = p.accent_soft;
    visuals.selection.stroke = Stroke::new(1.0_f32, p.accent);

    ctx.all_styles_mut(|style| {
        style.visuals = visuals.clone();
    });
}
