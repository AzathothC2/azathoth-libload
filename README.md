# Azathoth_libload

A cross-platform, dynamic binary loader for use in the [AzathothC2 framework](https://github.com/AzathothC2/)
It provides a flexible API for loading binaries at runtime, with optional hashing-based symbol resolution.


## Features
* **Hasher support** (_default enabled_, **uses `alloc`**): integrates the identifier hasher utilities from the [`azathoth_utils`](https://github.com/AzathothC2/azathoth_utils) crate for obfuscated symbol resolution.
* **`no_std` capable**: Doesn't rely on the `std` crate so it is suitable for embedd/restricted environments

## Installation
Add the crate via Cargo: 
```cargo add azathoth_libload```

Or manually in `Cargo.toml`: ```azathoth_libload = "0.1.0";```

## Status/Limits
* **Windows dynamic loading is fully implemented**
* **Linux dynamic loading is still in development** - current builds do not support Linux runtime loading (yet)

>[!WARNING]
> **Be advised that this is still a WIP crate and may change at any time! (Unstable)**

## License
MIT


## Changelog

* 0.1.0: Initial commit
* 0.1.1: Fixed `lib.rs` export issue and added changelog