mod utils;

#[cfg(feature = "hasher")]
pub use hashed::{get_proc_address, load_library, resolve_forwarder, find_api};
#[cfg(not(feature = "hasher"))]
pub use unhashed::{get_proc_address, load_library, resolve_forwarder, find_api};

#[cfg(feature = "hasher")]
pub mod hashed;

#[cfg(not(feature = "hasher"))]
pub mod unhashed;
