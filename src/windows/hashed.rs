use azathoth_core::os::Current::consts::IMAGE_DIRECTORY_ENTRY_EXPORT;
use azathoth_core::os::Current::structs::{IMAGE_EXPORT_DIRECTORY, LDR_DATA_TABLE_ENTRY, LIST_ENTRY};
use azathoth_utils::hasher::{FuncIdentifier, Hasher};
use crate::ident2val;
use crate::windows::utils::{copy_to_buf, get_nt_headers, get_peb, ptr_to_str, rva, strip_dll_suffix, to_ascii_uppercase_buf, ustr_to_str};

/// Resolves a function's address from a module's export table by hash or name.
///
/// Iterates through the export directory of the given module and returns
/// the function address matching the supplied identifier (hash, name, or bytes).
///
/// # Safety
/// - `base_address` must be a valid, mapped PE image in memory.
/// - The export directory must be readable and valid.
/// - Dereferencing invalid pointers is undefined behavior.
///
/// # Example
/// ```no_run
/// use azathoth_utils::crc32;
/// let addr = unsafe {
///     azathoth_libload::windows::get_proc_address(0x12345 as *mut u8, &crc32, b"LoadLibraryA")
/// };
/// ```
pub unsafe fn get_proc_address<'a, H, I>(base_address: *mut u8, hasher: &H, ident: I) -> Option<usize>
where
    H: Hasher,
    I: Into<
        FuncIdentifier<'a>>
{
    unsafe {
        let base = base_address as usize;
        let nt_headers = get_nt_headers(base_address)?;
        let export_entry =
            (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];

        let export_rva = export_entry.VirtualAddress;
        let export_size = export_entry.Size;
        let export_dir = rva::<IMAGE_EXPORT_DIRECTORY>(base, export_rva);
        let num_names = (*export_dir).NumberOfNames as usize;
        let num_funcs = (*export_dir).NumberOfFunctions as usize;

        let names = core::slice::from_raw_parts(rva::<u32>(base, (*export_dir).AddressOfNames), num_names);
        let ordinals = core::slice::from_raw_parts(
            rva::<u16>(base, (*export_dir).AddressOfNameOrdinals),
            num_names,
        );
        let funcs = core::slice::from_raw_parts(
            rva::<u32>(base, (*export_dir).AddressOfFunctions),
            num_funcs,
        );

        let identifier = ident2val(ident, hasher);
        for i in 0..num_names {
            let name_ptr = (base + names[i] as usize) as *const u8;
            let name = ptr_to_str(name_ptr)?;
            if identifier == hasher.hash(name) {

                let ordinal = ordinals[i] as usize;
                if ordinal >= funcs.len() {
                    return None;
                }

                let func_rva = funcs[ordinal];
                let func_addr = base + func_rva as usize;

                if func_rva >= export_rva && func_rva < export_rva + export_size {
                    let forwarder_str = ptr_to_str(rva::<u8>(base, func_rva))?;
                    return resolve_forwarder(forwarder_str, hasher);
                }

                return Some(func_addr);
            }
        }
        None
    }
}

/// Locates a loaded module in the PEB by the given identifier format
///
/// Walks the loader's InLoadOrderModuleList and compares hashed DLL names
/// against the supplied identifier. Returns the base address if found.
///
/// # Safety
/// - Relies on valid PEB and loader structures.
/// - `ustr_to_str` and string buffer handling are unsafe and must be correct.
///
/// # Example
/// ```no_run
/// use azathoth_utils::crc32;
/// use azathoth_libload::windows::load_library;
/// let base = unsafe {
///     load_library(b"kernel32.dll", &crc32)
/// };
/// ```
pub unsafe fn load_library<'a, H, I>(ident: I, hasher: &H) -> Option<*mut u8>
where
    H: Hasher,
    I: Into<FuncIdentifier<'a>> {
    unsafe {
        let peb = get_peb();
        let ldr = (*peb).Ldr;
        let list_head = &mut (*ldr).InLoadOrderModuleList as *mut LIST_ENTRY;
        let mut current = (*list_head).flink;

        let target_hash = match ident.into() {
            FuncIdentifier::Hashed(hash) => hash,
            FuncIdentifier::Name(name) => {
                hasher.hash(strip_dll_suffix(name))
            },
            FuncIdentifier::Bytes(bytes) => {
                let s = core::str::from_utf8_unchecked(&bytes);
                hasher.hash(strip_dll_suffix(s))
            },
        };
        while current != list_head {
            let entry = current as *const LDR_DATA_TABLE_ENTRY;
            let base_name = &(*entry).BaseDllName;
            if let Some(name) = ustr_to_str(base_name) {
                let mut buf = [0u8; 64];
                let _ = to_ascii_uppercase_buf(name, &mut buf)?;
                let str_from_buf = core::str::from_utf8(&buf).ok()?;
                let cleaned_str = str_from_buf.trim_end_matches(|c: char| c == '\0' || c.is_ascii_whitespace());
                let mut buf2 = [0u8; 64];
                let str_from_buf2 = copy_to_buf(cleaned_str, &mut buf2)?;
                let str_to_hash = strip_dll_suffix(str_from_buf2);
                let hash = hasher.hash(str_to_hash);
                if hash == target_hash {
                    return Some((*entry).DllBase as *mut u8);
                }
            }
            current = (*current).flink;
        }
        None
    }
}

/// Resolves a forwarded export by loading the target DLL and resolving the symbol.
///
/// Forwarded exports are entries in the export table pointing to another DLL's export.
///
/// # Safety
/// - Assumes `forwarder` is a valid "DLLName.SymbolName" string.
/// - Uses unsafe module loading and export resolution internally.
///
/// # Example
/// ```no_run
/// use azathoth_utils::crc32;
/// use azathoth_libload::windows::resolve_forwarder;
/// let addr = unsafe {
///     resolve_forwarder("KERNEL32.Sleep", &crc32)
/// };
/// ```
pub unsafe fn resolve_forwarder<H: Hasher>(forwarder: &str, hasher: &H) -> Option<usize> {
    let idx = forwarder.find('.')?;
    let dll_name_part = &forwarder[..idx];
    let symbol_part = &forwarder[idx + 1..];
    let base = unsafe { load_library(dll_name_part, hasher)? };
    if base.is_null() {
        return None;
    }
    unsafe { get_proc_address(base, hasher, symbol_part)}
}

/// Finds and casts a function in a module by hash or name.
///
/// A convenience wrapper around [`get_proc_address`] that directly returns
/// the function pointer as type `T`.
///
/// # Safety
/// - Caller must ensure `T` is the correct function signature for the resolved address.
/// - All safety notes from [`get_proc_address`] apply.
///
/// # Example
/// ```no_run
/// use azathoth_utils::crc32;
/// type SleepFn = unsafe extern "system" fn(u32);
/// let sleep: SleepFn = unsafe {
///     let kernel32_base = 0x123456 as *mut u8;
///     azathoth_libload::windows::find_api(kernel32_base, b"Sleep", &crc32).unwrap()
/// };
/// ```
pub unsafe fn find_api<'a, H, I, T>(base: *mut u8, ident: I, hasher: &H) -> Option<T>
where
    H: Hasher,
    I: Into<FuncIdentifier<'a>>,
{
    unsafe {
        let addr = get_proc_address(base, hasher, ident)?;
        Some(core::mem::transmute_copy::<_, T>(&addr))
    }
}