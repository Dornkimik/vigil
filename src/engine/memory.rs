//! A program that is packed or encrypted on disk has to unpack itself in memory before it
//! can run. A few seconds after it starts, the places where unpacked code ends up are read
//! and checked with the same rules as files: the program's own image (only when its file
//! looks packed) and private memory that can run code, which holds injected code, shellcode
//! and programs loaded without a file. Nothing is ever written to the process.

use crate::winapi::{ProcessMemory, Region};

/// The program's own image as it is in memory.
const MAX_IMAGE: usize = 32 << 20;
/// One private allocation.
const MAX_BLOCK: usize = 16 << 20;
/// Everything read from one process, so a game's gigabytes of memory stay unread.
const MAX_TOTAL: usize = 64 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockKind {
    /// The program's own image, after any unpacking.
    Image,
    /// Private memory that can run code.
    Private,
    /// Private memory where the program's image should be: its code was replaced
    /// (process hollowing).
    Replaced,
}

pub struct Block {
    pub kind: BlockKind,
    pub data: Vec<u8>,
}

/// Reads the memory worth checking. `image` also reads the program's own image, which
/// only differs from its file when the program unpacks itself.
pub fn read(process: &ProcessMemory, image: bool) -> Vec<Block> {
    let regions: Vec<Region> = process.regions().into_iter().filter(|r| r.readable).collect();
    let main = process.main_module().map(|(base, _)| base);
    let mut blocks = Vec::new();
    let mut total = 0;
    if image && let Some(base) = main {
        let data = gather(process, regions.iter().filter(|r| r.image && r.allocation == base), MAX_IMAGE);
        total += data.len();
        if !data.is_empty() {
            blocks.push(Block { kind: BlockKind::Image, data });
        }
    }
    let mut allocations: Vec<usize> = regions.iter().filter(|r| r.private && r.executable).map(|r| r.allocation).collect();
    allocations.dedup();
    for allocation in allocations {
        if total >= MAX_TOTAL {
            break;
        }
        // The whole allocation: a program loaded into memory keeps its data next to its code.
        let data = gather(process, regions.iter().filter(|r| r.private && r.allocation == allocation), MAX_BLOCK.min(MAX_TOTAL - total));
        total += data.len();
        let kind = if main == Some(allocation) { BlockKind::Replaced } else { BlockKind::Private };
        if !data.is_empty() {
            blocks.push(Block { kind, data });
        }
    }
    blocks
}

/// Contents of `regions` in address order, up to `limit` bytes. Unreadable ones are left out.
fn gather<'a>(process: &ProcessMemory, regions: impl Iterator<Item = &'a Region>, limit: usize) -> Vec<u8> {
    let mut data = Vec::new();
    for r in regions {
        let want = r.size.min(limit - data.len());
        if want == 0 {
            break;
        }
        data.extend(process.read(r.base, want).unwrap_or_default());
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr::null;
    use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc, VirtualFree};

    #[test]
    fn reads_programs_loaded_into_private_memory() {
        // Inert: headers and a marker, never executed.
        let mut payload = crate::engine::pe::tests::headers(false);
        payload.extend_from_slice(b"VIGIL-MEMORY-MARKER");
        let code = unsafe { VirtualAlloc(null(), 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) };
        assert!(!code.is_null());
        unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), code.cast(), payload.len()) };

        let process = ProcessMemory::open(std::process::id()).unwrap();
        let blocks = read(&process, true);
        assert!(blocks.iter().any(|b| b.kind == BlockKind::Private && b.data.starts_with(&payload)));
        let image = blocks.iter().find(|b| b.kind == BlockKind::Image).expect("own image");
        assert!(image.data.starts_with(b"MZ"));
        assert!(blocks.iter().map(|b| b.data.len()).sum::<usize>() <= MAX_TOTAL);
        // The image is only read when asked for.
        assert!(!read(&process, false).iter().any(|b| b.kind == BlockKind::Image));
        unsafe { VirtualFree(code, 0, MEM_RELEASE) };
    }
}
