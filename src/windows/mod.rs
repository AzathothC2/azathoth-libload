mod utils;

#[cfg(feature = "hasher")]
pub use hashed::{get_proc_address, load_library, resolve_forwarder, find_api};
#[cfg(not(feature = "hasher"))]
pub use unhashed::{get_proc_address, load_library, resolve_forwarder, find_api};
use crate::symbol::Symbol;

#[cfg(feature = "hasher")]
use azathoth_utils::hasher::FuncIdentifier;

#[cfg(feature = "hasher")]
pub mod hashed;

#[cfg(not(feature = "hasher"))]
pub mod unhashed;


pub struct WindowsInnerMemLibrary {
    handle: *mut u8,
}

impl WindowsInnerMemLibrary {

    #[cfg(not(feature = "hasher"))]
    pub fn get_symbol<T>(&self, symbol: &[u8]) -> Option<Symbol<T>> {

        None
    }

    #[cfg(feature = "hasher")]
    pub fn get_symbol<T>(&self, symbol: FuncIdentifier) -> Option<Symbol<T>> {
        None
    }

}