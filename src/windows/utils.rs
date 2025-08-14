use core::arch::asm;
use azathoth_core::os::Current::consts::{IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE};
use azathoth_core::os::Current::structs::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, PEB, UNICODE_STRING};


/// Computes a pointer to a value at a Relative Virtual Address from a
/// given base.
#[inline(always)]
#[unsafe(link_section = ".text")]
pub(super) fn rva<T>(base: usize, offset: u32) -> *const T {
    (base + offset as usize) as *const T
}

/// Computes a **mutable** pointer to a value at a Relative Virtual Address from a
/// given base.
#[inline(always)]
#[unsafe(link_section = ".text")]
pub(super) fn rva_mut<T>(base: usize, offset: u32) -> *mut T {
    (base + offset as usize) as *mut T
}


/// Interprets a Windows `UNICODE_STRING` as a `&str` without validation.
///
/// This function reads `s.Length/2` UTF-16 code units from `s.Buffer`, views
/// the underlying bytes, and then **unsafely** constructs a `&str` via
/// `from_utf8_unchecked`.
///
/// # Safety
/// - The function performs unchecked pointer/length operations and calls
///   `from_utf8_unchecked`.
/// - Callers must ensure:
///   - `s.Buffer` is valid for reading `s.Length` bytes.
///   - The memory does not outlive the returned `&str`.
///   - The pointed-to bytes are valid UTF-8 if you rely on UTF-8 semantics.
#[unsafe(link_section = ".text")]
pub(super) unsafe fn ustr_to_str(s: &UNICODE_STRING) -> Option<&str> {
    unsafe {
        if s.Buffer.is_null()  || s.Length == 0 {
            return None;
        }
        let len = (s.Length / 2) as usize;
        let utf16 = core::slice::from_raw_parts(s.Buffer, len);
        let bytes = core::slice::from_raw_parts(utf16.as_ptr() as *const u8, utf16.len() * 2);
        let mut actual_len = bytes.len();
        while actual_len > 0 && bytes[actual_len - 1] == 0 {
            actual_len -= 1;
        }
        Some(core::str::from_utf8_unchecked(bytes))
    }
}


/// Converts a string to uppercase
#[unsafe(link_section = ".text")]
pub(super) fn to_ascii_uppercase_buf<'a>(input: &str, out: &'a mut [u8]) -> Option<&'a [u8]> {
    let bytes = input.as_bytes();
    if bytes.len() > out.len() {
        return None;
    }

    for (i, &b) in bytes.iter().enumerate() {
        out[i] = if b'a' <= b && b <= b'z' {
            b - 32
        } else {
            b
        };
    }

    Some(&out[..bytes.len()])
}


/// Converts a raw C string pointer to a Rust string slice.
///
/// # Safety
/// The caller must ensure that the pointer is valid and points to
/// a null-terminated UTF-8 string.
#[inline(always)]
#[unsafe(link_section = ".text")]
pub(super) fn ptr_to_str(ptr: *const u8) -> Option<&'static str> {
    if ptr.is_null() {
        return None;
    }

    unsafe {
        core::ffi::CStr::from_ptr(ptr as *const i8)
            .to_str()
            .ok()
    }
}

#[unsafe(link_section = ".text")]
pub(super) fn get_dos_header(base_address: *mut u8) -> Option<*mut IMAGE_DOS_HEADER> {
    unsafe {
        let hdr = base_address as *mut IMAGE_DOS_HEADER;
        if (*hdr).e_magic != IMAGE_DOS_SIGNATURE {
            None
        } else {
            Some(hdr)
        }
    }
}

#[unsafe(link_section = ".text")]
pub(super) fn get_nt_headers(base_address: *mut u8) -> Option<*mut IMAGE_NT_HEADERS64> {
    unsafe {
        let dos_header = get_dos_header(base_address)?;
        let nt_headers =
            rva_mut::<IMAGE_NT_HEADERS64>(base_address as usize, (*dos_header).e_lfanew);
        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            None
        } else {
            Some(nt_headers)
        }
    }
}

#[inline(always)]
#[unsafe(link_section = ".text")]
pub(super) unsafe fn get_peb() -> *mut PEB {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            let peb: *mut PEB;
            asm!("mov {}, gs:[0x60]", out(reg) peb);
            peb
        }

        #[cfg(target_arch = "x86")]
        {
            let peb: *mut PEB;
            asm!("mov {}, fs:[0x30]", out(reg) peb);
            peb
        }
    }
}

#[inline(always)]
#[unsafe(link_section = ".text")]
pub(super) fn strip_dll_suffix(name: &str) -> &str {
    if let Some(idx) = name.as_bytes()
        .windows(4)
        .position(|w| w.eq_ignore_ascii_case(b".DLL")) {
        &name[..idx]
    } else {
        name
    }
}

#[inline(always)]
#[unsafe(link_section = ".text")]
pub(super) fn copy_to_buf<'a>(src: &str, buf: &'a mut [u8; 64]) -> Option<&'a str> {
    let len = src
        .bytes()
        .filter(|&b| b != 0)
        .take(buf.len())
        .enumerate()
        .map(|(i, b)| buf[i] = b)
        .count();
    core::str::from_utf8(&buf[..len]).ok()
}