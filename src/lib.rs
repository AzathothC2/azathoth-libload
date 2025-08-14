#![no_std]

#[cfg(feature="hasher")]
extern crate alloc;

#[cfg(target_os = "windows")]
pub mod windows;

use azathoth_utils::hasher::{FuncIdentifier, Hasher};
#[cfg(target_os = "windows")]
pub use windows::{get_proc_address, load_library, resolve_forwarder};

#[cfg(target_os="linux")]
pub mod linux;

pub fn ident2val<'a, I, H>(ident: I, hasher: &H) -> u32
where
    H: Hasher,
    I: Into<FuncIdentifier<'a>> {
    match ident.into() {
        FuncIdentifier::Bytes(bytes) => hasher.hash_bytes(bytes),
        FuncIdentifier::Hashed(val) => val,
        FuncIdentifier::Name(name) => hasher.hash(name),
    }
}