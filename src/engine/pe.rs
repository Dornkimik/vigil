//! Structural heuristics for Windows executables.

use super::Finding;
use goblin::pe::{PE, options::ParseOptions};
use std::collections::HashSet;

const SCN_EXECUTE: u32 = 0x2000_0000;
const SCN_WRITE: u32 = 0x8000_0000;

pub fn analyze(data: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(f) = inflated(data) {
        findings.push(f);
    }

    let opts = ParseOptions::default()
        .with_parse_mode(goblin::options::ParseMode::Permissive)
        .with_parse_resources(false)
        .with_parse_tls_data(false);
    let pe = match PE::parse_with_opts(data, &opts) {
        Ok(pe) => pe,
        Err(_) => return findings,
    };

    let is_dotnet = pe.clr_data.is_some();
    let imports: HashSet<String> = pe.imports.iter().map(|i| i.name.to_ascii_lowercase()).collect();
    let has = |n: &str| imports.contains(n);
    let any = |ns: &[&str]| ns.iter().any(|n| has(n));

    if any(&["virtualallocex", "ntallocatevirtualmemory"])
        && any(&["writeprocessmemory", "ntwritevirtualmemory"])
        && any(&["createremotethread", "ntcreatethreadex", "queueuserapc", "setthreadcontext", "rtlcreateuserthread"])
    {
        findings.push(Finding::new("pe.injection", "Can inject code into other processes", 15));
    }
    if any(&["ntunmapviewofsection", "zwunmapviewofsection"]) && any(&["setthreadcontext", "wow64setthreadcontext"]) && has("resumethread")
    {
        findings.push(Finding::new("pe.hollowing", "Process hollowing API combination", 30));
    }
    let mut max_entropy = 0.0f64;
    let mut packer = None;
    for s in &pe.sections {
        let name = String::from_utf8_lossy(&s.name).trim_end_matches('\0').to_string();
        let lname = name.to_ascii_lowercase();
        if packer.is_none() && ["upx0", "upx1", ".mpress1", ".aspack", ".petite", ".nsp0", ".packed"].contains(&lname.as_str()) {
            packer = Some(name.clone());
        }
        if s.characteristics & SCN_EXECUTE != 0 && s.characteristics & SCN_WRITE != 0 && !findings.iter().any(|f| f.id == "pe.rwx") {
            findings.push(Finding::new("pe.rwx", format!("Section {name} is both writable and executable"), 5));
        }
        let (start, len) = (s.pointer_to_raw_data as usize, s.size_of_raw_data as usize);
        if s.characteristics & SCN_EXECUTE != 0 && len > 4096 && start.saturating_add(len) <= data.len() {
            max_entropy = max_entropy.max(entropy(&data[start..start + len]));
        }
    }
    if let Some(p) = packer {
        findings.push(Finding::new("pe.packer", format!("Packed with a known packer (section {p})"), 10));
    }
    if max_entropy > 7.2 {
        findings.push(Finding::new("pe.high_entropy", format!("Code is compressed or encrypted (entropy {max_entropy:.2})"), 10));
    }
    if !is_dotnet && !pe.is_lib && imports.len() < 3 {
        findings.push(Finding::new("pe.few_imports", "Almost no imported functions (typical for packed loaders)", 0));
    }

    findings
}

/// Malware is often padded to hundreds of MB so it exceeds AV upload/scan limits.
pub fn inflated(data: &[u8]) -> Option<Finding> {
    if data.len() < 100 << 20 {
        return None;
    }
    let tail = &data[data.len() - (4 << 20)..];
    let mut counts = [0usize; 256];
    for &b in tail {
        counts[b as usize] += 1;
    }
    let top = *counts.iter().max().unwrap();
    (top * 100 / tail.len() >= 99).then(|| {
        Finding::new("pe.inflated", format!("Padded with junk to {} MB (used to evade antivirus size limits)", data.len() >> 20), 10)
    })
}

pub fn entropy(data: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}
