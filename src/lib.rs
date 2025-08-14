#![no_std]

#[cfg(feature="hasher")]
extern crate alloc;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows::{get_proc_address, load_library, resolve_forwarder};

#[cfg(target_os="linux")]
pub mod linux;