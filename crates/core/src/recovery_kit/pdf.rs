//! Renders the recovery kit as a printable A4 PDF, designed like a passport page —
//! the one artifact the user prints. Uses built-in Courier (a monospace) so no font
//! binary needs vendoring; the on-screen UI still uses JetBrains Mono. A QR code of
//! the recovery key is drawn as filled modules for phone-camera restore.

use super::{encode, RecoveryKey};
use printpdf::path::{PaintMode, WindingOrder};
use printpdf::{BuiltinFont, Color, Mm, PdfDocument, Point, Polygon, Rgb};
use qrcode::types::Color as QrColor;
use qrcode::QrCode;

// A4 in millimetres.
const PAGE_W: f32 = 210.0;
const PAGE_H: f32 = 297.0;

fn ink() -> Color {
    Color::Rgb(Rgb::new(0.04, 0.06, 0.08, None)) // near-black blue-slate
}
fn accent() -> Color {
    Color::Rgb(Rgb::new(0.05, 0.55, 0.62, None)) // print-safe cyan
}
fn faint() -> Color {
    Color::Rgb(Rgb::new(0.85, 0.88, 0.91, None))
}

/// Render the recovery kit PDF. `display` is the `SNTL-…` recovery key string;
/// `account_email` and `created` are shown for provenance (created = ISO date).
pub fn render_kit_pdf(display: &str, account_email: &str, created_iso: &str) -> Vec<u8> {
    let (doc, page, layer) =
        PdfDocument::new("SENTINEL Recovery Kit", Mm(PAGE_W), Mm(PAGE_H), "kit");
    let l = doc.get_page(page).get_layer(layer);

    let courier = doc
        .add_builtin_font(BuiltinFont::Courier)
        .expect("builtin Courier");
    let courier_bold = doc
        .add_builtin_font(BuiltinFont::CourierBold)
        .expect("builtin CourierBold");
    let helv = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .expect("builtin Helvetica");
    let helv_bold = doc
        .add_builtin_font(BuiltinFont::HelveticaBold)
        .expect("builtin HelveticaBold");

    // --- header band --------------------------------------------------------
    fill_rect(&l, 0.0, PAGE_H - 32.0, PAGE_W, 32.0, ink());
    l.set_fill_color(Color::Rgb(Rgb::new(1.0, 1.0, 1.0, None)));
    l.use_text("SENTINEL", 26.0, Mm(18.0), Mm(PAGE_H - 20.0), &helv_bold);
    l.set_fill_color(accent());
    l.use_text(
        "RECOVERY KIT",
        12.0,
        Mm(78.0),
        Mm(PAGE_H - 19.0),
        &helv_bold,
    );

    // --- outer border (passport frame) --------------------------------------
    stroke_rect(&l, 12.0, 12.0, PAGE_W - 24.0, PAGE_H - 24.0, accent(), 1.2);
    stroke_rect(&l, 15.0, 15.0, PAGE_W - 30.0, PAGE_H - 30.0, faint(), 0.4);

    // --- explanatory copy ---------------------------------------------------
    l.set_fill_color(ink());
    let intro = [
        "This is the break-glass key to your SENTINEL vault.",
        "It is shown only once and is NOT stored anywhere online.",
        "Keep this sheet somewhere safe and private. Anyone who has",
        "it, plus your device, can unlock your vault. Lose every",
        "unlock method and this key, and the vault is gone forever.",
    ];
    let mut y = PAGE_H - 48.0;
    for line in intro {
        l.use_text(line, 11.0, Mm(20.0), Mm(y), &helv);
        y -= 6.2;
    }

    // --- the key, large and grouped -----------------------------------------
    y -= 6.0;
    l.set_fill_color(accent());
    l.use_text("RECOVERY KEY", 10.0, Mm(20.0), Mm(y), &helv_bold);
    y -= 10.0;
    // Panel behind the key.
    fill_rect(
        &l,
        18.0,
        y - 4.0,
        PAGE_W - 36.0,
        14.0,
        Color::Rgb(Rgb::new(0.96, 0.98, 0.99, None)),
    );
    l.set_fill_color(ink());
    l.use_text(display, 15.0, Mm(22.0), Mm(y + 1.5), &courier_bold);

    // --- QR code ------------------------------------------------------------
    y -= 20.0;
    let qr_side = 60.0;
    let qr_x = (PAGE_W - qr_side) / 2.0;
    let qr_y = y - qr_side;
    draw_qr(&l, display, qr_x, qr_y, qr_side);
    l.set_fill_color(ink());
    l.use_text(
        "Scan to restore on a new device",
        9.0,
        Mm(qr_x - 4.0),
        Mm(qr_y - 6.0),
        &helv,
    );

    // --- provenance footer --------------------------------------------------
    l.set_fill_color(ink());
    l.use_text(
        format!("Account: {account_email}"),
        9.0,
        Mm(20.0),
        Mm(30.0),
        &courier,
    );
    l.use_text(
        format!("Generated: {created_iso}"),
        9.0,
        Mm(20.0),
        Mm(24.0),
        &courier,
    );
    l.use_text(
        "SENTINEL v1  •  keep offline  •  do not photograph and store in the cloud",
        8.0,
        Mm(20.0),
        Mm(18.5),
        &helv,
    );

    doc.save_to_bytes().expect("serialize recovery PDF")
}

/// Convenience: render straight from a `RecoveryKey`.
pub fn render_for_key(rk: &RecoveryKey, account_email: &str, created_iso: &str) -> Vec<u8> {
    render_kit_pdf(&encode(rk), account_email, created_iso)
}

fn fill_rect(l: &printpdf::PdfLayerReference, x: f32, y: f32, w: f32, h: f32, c: Color) {
    l.set_fill_color(c);
    let poly = Polygon {
        rings: vec![vec![
            (Point::new(Mm(x), Mm(y)), false),
            (Point::new(Mm(x + w), Mm(y)), false),
            (Point::new(Mm(x + w), Mm(y + h)), false),
            (Point::new(Mm(x), Mm(y + h)), false),
        ]],
        mode: PaintMode::Fill,
        winding_order: WindingOrder::NonZero,
    };
    l.add_polygon(poly);
}

fn stroke_rect(l: &printpdf::PdfLayerReference, x: f32, y: f32, w: f32, h: f32, c: Color, t: f32) {
    l.set_outline_color(c);
    l.set_outline_thickness(t);
    let poly = Polygon {
        rings: vec![vec![
            (Point::new(Mm(x), Mm(y)), false),
            (Point::new(Mm(x + w), Mm(y)), false),
            (Point::new(Mm(x + w), Mm(y + h)), false),
            (Point::new(Mm(x), Mm(y + h)), false),
        ]],
        mode: PaintMode::Stroke,
        winding_order: WindingOrder::NonZero,
    };
    l.add_polygon(poly);
}

fn draw_qr(l: &printpdf::PdfLayerReference, data: &str, x: f32, y: f32, side: f32) {
    let code = match QrCode::new(data.as_bytes()) {
        Ok(c) => c,
        Err(_) => return,
    };
    let w = code.width();
    let colors = code.to_colors();
    let module = side / w as f32;
    // Quiet-zone background.
    fill_rect(
        l,
        x - module,
        y - module,
        side + 2.0 * module,
        side + 2.0 * module,
        Color::Rgb(Rgb::new(1.0, 1.0, 1.0, None)),
    );
    l.set_fill_color(ink());
    for row in 0..w {
        for col in 0..w {
            if colors[row * w + col] == QrColor::Dark {
                // PDF y grows upward; flip rows.
                let px = x + col as f32 * module;
                let py = y + (w - 1 - row) as f32 * module;
                let poly = Polygon {
                    rings: vec![vec![
                        (Point::new(Mm(px), Mm(py)), false),
                        (Point::new(Mm(px + module), Mm(py)), false),
                        (Point::new(Mm(px + module), Mm(py + module)), false),
                        (Point::new(Mm(px), Mm(py + module)), false),
                    ]],
                    mode: PaintMode::Fill,
                    winding_order: WindingOrder::NonZero,
                };
                l.add_polygon(poly);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_valid_pdf_bytes() {
        let rk = RecoveryKey::from_bytes([0x42; 16]);
        let bytes = render_for_key(&rk, "user@example.com", "2026-07-18");
        // Valid PDFs start with "%PDF-" and end near "%%EOF".
        assert!(bytes.starts_with(b"%PDF-"), "missing PDF header");
        assert!(
            bytes.len() > 1500,
            "PDF unexpectedly tiny: {} bytes",
            bytes.len()
        );
        let tail = &bytes[bytes.len().saturating_sub(1024)..];
        assert!(
            tail.windows(5).any(|w| w == b"%%EOF"),
            "missing %%EOF trailer"
        );
    }

    #[test]
    fn does_not_leak_key_bytes_as_plaintext() {
        // The rendered PDF contains the *encoded* recovery string (that is the point of
        // a printed kit), but must not contain the raw 16 key bytes verbatim.
        let rk = RecoveryKey::from_bytes([0x11; 16]);
        let bytes = render_for_key(&rk, "u@e.com", "2026-07-18");
        let raw = [0x11u8; 16];
        assert!(
            !bytes.windows(16).any(|w| w == raw),
            "raw key bytes leaked into PDF stream"
        );
    }
}
