use std::{env, fs, path::PathBuf};

#[allow(dead_code)]
mod icon {
    include!("src/icon.rs");
}

/// Must match `engine::rules::decode`.
fn obfuscate(data: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ (0xA5u8.wrapping_add((i as u8).wrapping_mul(31))))
        .collect()
}

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Ship the detection rules obfuscated so the scanner binary itself does not
    // contain plaintext malware indicators (which would make other AV engines,
    // and Vigil itself, flag it).
    println!("cargo:rerun-if-changed=rules/default.rules");
    let rules = fs::read("rules/default.rules").expect("rules/default.rules missing");
    fs::write(out.join("rules.bin"), obfuscate(&rules)).unwrap();

    println!("cargo:rerun-if-changed=src/icon.rs");
    let images: Vec<(u32, Vec<u8>)> = [16, 24, 32, 48, 64, 256]
        .iter()
        .map(|&s| (s, icon::shield_rgba(s, icon::GREEN_TOP, icon::GREEN_BOTTOM)))
        .collect();
    let ico_path = out.join("vigil.ico");
    fs::write(&ico_path, icon::ico_file(&images)).unwrap();

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon(ico_path.to_str().unwrap());
        res.set("ProductName", "Vigil");
        res.set("FileDescription", "Vigil - lightweight malware scanner");
        // The icon is cosmetic; don't fail the build when no resource compiler exists.
        if let Err(e) = res.compile() {
            println!("cargo:warning=could not embed exe icon: {e}");
        }
    }
}
