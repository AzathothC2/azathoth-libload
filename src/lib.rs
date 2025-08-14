#![no_std]

#[cfg(feature="hasher")]
extern crate alloc;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os="linux")]
pub mod linux;