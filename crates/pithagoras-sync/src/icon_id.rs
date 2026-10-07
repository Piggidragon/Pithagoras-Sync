// Read by `build.rs` too (`include!`), which writes the resource.

/// The resource id of the program's icon group in the Windows `.exe`:
/// `build.rs` writes it, the message boxes name it (`MB_USERICON`).
pub const ICON_ID: u16 = 1;
