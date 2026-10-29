// Procedural app icon: a rounded shield with a check mark.
//
// This file is also `include!`d by build.rs to produce the .ico embedded in the
// executable, so it must not reference anything outside of `std`.

/// Rasterizes the shield into a `size`x`size` RGBA buffer (4x4 supersampled).
pub fn shield_rgba(size: u32, top: [u8; 3], bottom: [u8; 3]) -> Vec<u8> {
    const SS: u32 = 4;
    let mut out = vec![0u8; (size * size * 4) as usize];
    for py in 0..size {
        for px in 0..size {
            let (mut shield, mut check) = (0u32, 0u32);
            for sy in 0..SS {
                for sx in 0..SS {
                    let x = (px as f32 + (sx as f32 + 0.5) / SS as f32) / size as f32;
                    let y = (py as f32 + (sy as f32 + 0.5) / SS as f32) / size as f32;
                    if inside_shield(x, y) {
                        shield += 1;
                        if inside_check(x, y) {
                            check += 1;
                        }
                    }
                }
            }
            let n = (SS * SS) as f32;
            let alpha = shield as f32 / n;
            if alpha == 0.0 {
                continue;
            }
            let t = py as f32 / size as f32;
            let mut rgb = [0f32; 3];
            for c in 0..3 {
                rgb[c] = top[c] as f32 * (1.0 - t) + bottom[c] as f32 * t;
            }
            let w = check as f32 / shield as f32;
            for c in 0..3 {
                rgb[c] = rgb[c] * (1.0 - w) + 255.0 * w;
            }
            let i = ((py * size + px) * 4) as usize;
            out[i] = rgb[0] as u8;
            out[i + 1] = rgb[1] as u8;
            out[i + 2] = rgb[2] as u8;
            out[i + 3] = (alpha * 255.0) as u8;
        }
    }
    out
}

fn inside_shield(x: f32, y: f32) -> bool {
    let (top, mid, bottom, half) = (0.08, 0.52, 0.94, 0.38);
    if y < top || y > bottom {
        return false;
    }
    let dx = (x - 0.5).abs();
    if y < mid {
        // Rounded top corners.
        let r = 0.12;
        let cy = top + r;
        let cx = half - r;
        if y < cy && dx > cx {
            return (dx - cx).powi(2) + (y - cy).powi(2) <= r * r;
        }
        return dx <= half;
    }
    let t = (y - mid) / (bottom - mid);
    dx <= half * (1.0 - t * t)
}

fn inside_check(x: f32, y: f32) -> bool {
    let th = 0.085;
    seg_dist(x, y, 0.31, 0.50, 0.45, 0.64) < th / 2.0 || seg_dist(x, y, 0.45, 0.64, 0.70, 0.36) < th / 2.0
}

fn seg_dist(px: f32, py: f32, ax: f32, ay: f32, bx: f32, by: f32) -> f32 {
    let (vx, vy) = (bx - ax, by - ay);
    let t = (((px - ax) * vx + (py - ay) * vy) / (vx * vx + vy * vy)).clamp(0.0, 1.0);
    let (cx, cy) = (ax + t * vx, ay + t * vy);
    ((px - cx).powi(2) + (py - cy).powi(2)).sqrt()
}

/// Encodes RGBA pixels as an icon-resource DIB (BITMAPINFOHEADER + BGRA + AND mask),
/// the format used both inside .ico files and by CreateIconFromResourceEx.
pub fn ico_dib(size: u32, rgba: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    let mask_row = ((size + 31) / 32) * 4;
    v.extend_from_slice(&40u32.to_le_bytes());
    v.extend_from_slice(&(size as i32).to_le_bytes());
    v.extend_from_slice(&((size * 2) as i32).to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&32u16.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&(size * size * 4 + mask_row * size).to_le_bytes());
    v.extend_from_slice(&[0u8; 16]);
    for y in (0..size).rev() {
        for x in 0..size {
            let i = ((y * size + x) * 4) as usize;
            v.extend_from_slice(&[rgba[i + 2], rgba[i + 1], rgba[i], rgba[i + 3]]);
        }
    }
    v.extend(std::iter::repeat_n(0u8, (mask_row * size) as usize));
    v
}

/// Builds a complete multi-resolution .ico file (used by build.rs).
#[allow(dead_code)]
pub fn ico_file(images: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let dibs: Vec<(u32, Vec<u8>)> = images.iter().map(|(s, px)| (*s, ico_dib(*s, px))).collect();
    let mut v = Vec::new();
    v.extend_from_slice(&[0, 0, 1, 0]);
    v.extend_from_slice(&(dibs.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * dibs.len() as u32;
    for (s, dib) in &dibs {
        let dim = if *s >= 256 { 0 } else { *s as u8 };
        v.extend_from_slice(&[dim, dim, 0, 0]);
        v.extend_from_slice(&1u16.to_le_bytes());
        v.extend_from_slice(&32u16.to_le_bytes());
        v.extend_from_slice(&(dib.len() as u32).to_le_bytes());
        v.extend_from_slice(&offset.to_le_bytes());
        offset += dib.len() as u32;
    }
    for (_, dib) in &dibs {
        v.extend_from_slice(dib);
    }
    v
}

pub const GREEN_TOP: [u8; 3] = [0x4a, 0xe3, 0xa5];
pub const GREEN_BOTTOM: [u8; 3] = [0x1f, 0xa8, 0x8a];
pub const GRAY_TOP: [u8; 3] = [0x9a, 0xa0, 0xaa];
pub const GRAY_BOTTOM: [u8; 3] = [0x6b, 0x71, 0x7c];
pub const RED_TOP: [u8; 3] = [0xff, 0x6b, 0x6b];
pub const RED_BOTTOM: [u8; 3] = [0xd0, 0x3b, 0x4a];
