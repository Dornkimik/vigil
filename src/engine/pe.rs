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
    let syscall_host = pe.name.is_some_and(|n| n.eq_ignore_ascii_case("ntdll.dll") || n.eq_ignore_ascii_case("win32u.dll"));
    if pe.is_64 && !syscall_host {
        let stubs: usize = pe
            .sections
            .iter()
            .filter(|s| s.characteristics & SCN_EXECUTE != 0)
            .filter_map(|s| data.get(s.pointer_to_raw_data as usize..)?.get(..s.size_of_raw_data as usize))
            .map(syscall_stubs)
            .sum();
        if stubs >= 2 {
            findings.push(Finding::new(
                "pe.direct_syscalls",
                format!("Makes {stubs} system calls directly instead of through ntdll (bypasses security hooks)"),
                25,
            ));
        }
    }
    let cert_dir = pe.header.optional_header.and_then(|o| o.data_directories.get_certificate_table().copied());
    findings.extend(cert_dir.and_then(|d| certificate_finding(data, d.virtual_address as usize, d.size as usize)));

    findings
}

/// Some vendors keep small tags (installer attribution, anti-cheat integrity records) in the
/// signature block. A payload hidden there is large and encrypted.
fn certificate_finding(data: &[u8], offset: usize, size: usize) -> Option<Finding> {
    let hidden = certificate_slack(data, offset, size)?;
    if hidden.len() <= 64 || hidden.iter().all(|&b| b == 0) {
        return None;
    }
    let n = hidden.len();
    Some(if (n >= 1024 && entropy(&hidden) >= 6.5) || n >= 64 << 10 {
        Finding::new(
            "pe.cert_smuggling",
            format!("Hides {n} bytes of encrypted data inside its signature block (a signed file can carry a payload this way)"),
            40,
        )
    } else {
        Finding::new("pe.cert_tag", format!("Signature block carries {n} bytes of extra data (some vendors store tags there)"), 0)
    })
}

/// Where the code and signature of a PE file end. Anything after that is overlay,
/// where junk padding goes.
pub fn image_end(data: &[u8]) -> usize {
    let opts = ParseOptions::default()
        .with_parse_mode(goblin::options::ParseMode::Permissive)
        .with_parse_resources(false)
        .with_parse_tls_data(false);
    let Ok(pe) = PE::parse_with_opts(data, &opts) else { return data.len() };
    let sections = pe.sections.iter().map(|s| s.pointer_to_raw_data as usize + s.size_of_raw_data as usize);
    let cert = pe
        .header
        .optional_header
        .and_then(|o| o.data_directories.get_certificate_table().copied())
        .map(|d| d.virtual_address as usize + d.size as usize);
    sections.chain(cert).max().unwrap_or(data.len()).clamp(4096.min(data.len()), data.len())
}

/// Counts x64 `mov r10, rcx; mov eax, <number>` stubs followed by `syscall` or a jump
/// into ntdll. Outside ntdll these mean the program calls the kernel itself.
fn syscall_stubs(code: &[u8]) -> usize {
    code.windows(8)
        .enumerate()
        .filter(|(_, w)| w[..4] == [0x4C, 0x8B, 0xD1, 0xB8] && w[6..] == [0, 0])
        .filter(|(i, _)| {
            // syscall | jmp [rip+x] | jmp r10 / jmp r11
            let tail = &code[i + 8..code.len().min(i + 32)];
            tail.windows(2).any(|p| matches!(p, [0x0F, 0x05] | [0xFF, 0x25]))
                || tail.windows(3).any(|p| matches!(p, [0x41, 0xFF, 0xE2 | 0xE3]))
        })
        .count()
}

/// Windows doesn't verify bytes inside the signature block (WIN_CERTIFICATE) beyond
/// the PKCS#7 blob, so data put there leaves the signature valid. Returns those bytes,
/// leaving out alignment padding.
fn certificate_slack(data: &[u8], offset: usize, size: usize) -> Option<Vec<u8>> {
    let table = data.get(offset..offset.checked_add(size)?)?;
    let mut pos = 0;
    let mut hidden = Vec::new();
    while pos + 8 <= table.len() {
        let len = u32::from_le_bytes(table[pos..pos + 4].try_into().unwrap()) as usize;
        // Whatever doesn't parse as a certificate entry is hidden data too.
        let Some(entry) = table.get(pos + 8..pos + len).filter(|_| len > 8) else { break };
        let used = der_len(entry).unwrap_or(entry.len()).min(entry.len());
        hidden.extend_from_slice(&entry[used..]);
        pos = (pos + len + 7) & !7;
    }
    hidden.extend_from_slice(table.get(pos..).unwrap_or_default());
    Some(hidden)
}

/// Total length of a DER SEQUENCE (header included).
fn der_len(b: &[u8]) -> Option<usize> {
    if *b.first()? != 0x30 {
        return None;
    }
    let first = *b.get(1)? as usize;
    if first < 0x80 {
        return Some(2 + first);
    }
    let n = first & 0x7F;
    if n == 0 || n > 4 {
        return None;
    }
    let len = b.get(2..2 + n)?.iter().fold(0usize, |acc, &x| acc << 8 | x as usize);
    Some(2 + n + len)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Two x64 syscall stubs, as SysWhispers-style tools emit them.
    const STUBS: [u8; 22] = [
        0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, // NtAllocateVirtualMemory
        0x4C, 0x8B, 0xD1, 0xB8, 0x3A, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, // NtWriteVirtualMemory
    ];

    #[test]
    fn counts_direct_syscall_stubs() {
        assert_eq!(syscall_stubs(&STUBS), 2);
        // mov r10, rcx; mov eax, n without a following syscall or jump is ordinary code.
        assert_eq!(syscall_stubs(&[0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0, 0, 0, 0xC3, 0x90, 0x90]), 0);
        // Indirect syscalls jump into ntdll instead.
        assert_eq!(syscall_stubs(&[0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0, 0, 0, 0x41, 0xFF, 0xE3]), 1);
    }

    fn win_certificate(der_body: usize, extra: &[u8]) -> Vec<u8> {
        let mut der = vec![0x30, 0x82, (der_body >> 8) as u8, der_body as u8];
        der.resize(4 + der_body, 0x11);
        let len = 8 + der.len() + extra.len();
        let mut entry = (len as u32).to_le_bytes().to_vec();
        entry.extend_from_slice(&[0x00, 0x02, 0x02, 0x00]);
        entry.extend_from_slice(&der);
        entry.extend_from_slice(extra);
        entry.resize((entry.len() + 7) & !7, 0);
        entry
    }

    /// Stand-in for an encrypted payload: xorshift output has near-maximal entropy.
    fn random_bytes(n: usize) -> Vec<u8> {
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    fn finding_id(table: &[u8]) -> Option<String> {
        certificate_finding(table, 0, table.len()).map(|f| f.id)
    }

    #[test]
    fn finds_payloads_hidden_in_the_signature_block() {
        assert_eq!(finding_id(&win_certificate(1000, &[])), None);
        assert_eq!(finding_id(&win_certificate(1000, &[0; 200])), None);
        let payload = win_certificate(1000, &random_bytes(4096));
        assert_eq!(certificate_slack(&payload, 0, payload.len()).unwrap().len(), 4096);
        assert_eq!(finding_id(&payload).as_deref(), Some("pe.cert_smuggling"));
        // Data after the last entry but inside the declared table counts too.
        let mut trailing = win_certificate(1000, &[]);
        trailing.extend_from_slice(&random_bytes(2048));
        assert_eq!(finding_id(&trailing).as_deref(), Some("pe.cert_smuggling"));
    }

    #[test]
    fn small_vendor_tags_in_the_signature_block_are_only_noted() {
        // Anti-cheat integrity record: magic, length, 64 bytes of hash.
        let mut record = vec![0xEF, 0xCD, 0xAB, 0x89, 0x40, 0, 0, 0];
        record.extend(random_bytes(64));
        assert_eq!(finding_id(&win_certificate(1000, &record)).as_deref(), Some("pe.cert_tag"));
        // Installer attribution tag: readable text, however long.
        let tag = "Gact2.0Omaha appguid={00000000-0000-0000-0000-000000000000}&lang=en&browser=4&usagestats=1".repeat(20);
        assert_eq!(finding_id(&win_certificate(1000, tag.as_bytes())).as_deref(), Some("pe.cert_tag"));
    }

    #[test]
    fn padding_appended_to_a_program_is_trimmed_off() {
        let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let end = image_end(&exe);
        assert!(end > 4096 && end <= exe.len());
        let mut padded = exe.clone();
        padded.resize(exe.len() + (1 << 20), 0);
        assert_eq!(image_end(&padded), end);
        // An ordinary Rust program has no direct syscalls or hidden signature data.
        let findings = analyze(&exe);
        assert!(!findings.iter().any(|f| f.id == "pe.direct_syscalls" || f.id == "pe.cert_smuggling"), "{findings:?}");
    }
}
