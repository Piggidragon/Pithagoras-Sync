//! Windows (MSVC): the program's icon as a resource, so Explorer, the Task
//! Manager and the message boxes show it. The `.res` file is written here from
//! `assets/pithagoras-sync.ico` (a resource compiler would do the same) and
//! handed to the linker, which takes `.res` files as they are. Other targets
//! get nothing.

use std::path::PathBuf;

/// The `.ico` the resource is made of.
const ICO: &str = "../../assets/pithagoras-sync.ico";
/// The resource id of the icon group (`dialogs.rs` names it for the boxes).
const ICON_ID: u16 = 1;

const RT_ICON: u16 = 3;
const RT_GROUP_ICON: u16 = 14;
/// The memory flags resource compilers give an image (MOVEABLE | DISCARDABLE)
/// and the group (MOVEABLE | PURE | DISCARDABLE).
const IMAGE_FLAGS: u16 = 0x1010;
const GROUP_FLAGS: u16 = 0x1030;

fn main() {
    println!("cargo:rerun-if-changed={ICO}");
    println!("cargo:rerun-if-changed=build.rs");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if os != "windows" || env != "msvc" {
        return;
    }
    let ico = std::fs::read(ICO).expect("assets/pithagoras-sync.ico");
    let res = resource(&ico).expect("assets/pithagoras-sync.ico is not an icon file");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR")).join("icon.res");
    std::fs::write(&out, res).expect("write icon.res");
    println!("cargo:rustc-link-arg-bins={}", out.display());
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// One resource entry: its header (both ids numeric, language neutral), the
/// data, and padding to four bytes.
fn entry(out: &mut Vec<u8>, kind: u16, id: u16, flags: u16, data: &[u8]) {
    out.extend((data.len() as u32).to_le_bytes()); // DataSize
    out.extend(32u32.to_le_bytes()); // HeaderSize
    out.extend(
        [0xffff, kind, 0xffff, id]
            .iter()
            .flat_map(|w| w.to_le_bytes()),
    );
    out.extend(0u32.to_le_bytes()); // DataVersion
    out.extend(flags.to_le_bytes());
    out.extend(0u16.to_le_bytes()); // LanguageId: neutral
    out.extend(0u32.to_le_bytes()); // Version
    out.extend(0u32.to_le_bytes()); // Characteristics
    out.extend(data);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// The `.res` of an `.ico`: each image an `RT_ICON` (ids 1, 2, ...), and the
/// `RT_GROUP_ICON` `ICON_ID` that lists them, as `ICON` in an `.rc` file gives.
fn resource(ico: &[u8]) -> Option<Vec<u8>> {
    if u16_at(ico, 0)? != 0 || u16_at(ico, 2)? != 1 {
        return None;
    }
    let count = u16_at(ico, 4)?;
    let mut out = Vec::new();
    // A .res file starts with an empty entry.
    entry(&mut out, 0, 0, 0, &[]);
    let mut group = Vec::new();
    group.extend([0u16, 1, count].iter().flat_map(|w| w.to_le_bytes()));
    for i in 0..count {
        let e = 6 + 16 * i as usize;
        let dir = ico.get(e..e + 12)?;
        let size = u32_at(ico, e + 8)? as usize;
        let at = u32_at(ico, e + 12)? as usize;
        let image = ico.get(at..at.checked_add(size)?)?;
        entry(&mut out, RT_ICON, i + 1, IMAGE_FLAGS, image);
        // The directory entry as it was, with the resource id for the offset.
        group.extend(dir);
        group.extend((i + 1).to_le_bytes());
    }
    entry(&mut out, RT_GROUP_ICON, ICON_ID, GROUP_FLAGS, &group);
    Some(out)
}
