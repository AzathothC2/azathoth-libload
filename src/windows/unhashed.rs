use azathoth_core::os::Current::consts::IMAGE_DIRECTORY_ENTRY_EXPORT;
use azathoth_core::os::Current::structs::{IMAGE_EXPORT_DIRECTORY, LDR_DATA_TABLE_ENTRY, LIST_ENTRY};
use crate::windows::utils::{get_nt_headers, get_peb, ptr_to_str, rva, strip_dll_suffix, to_ascii_uppercase_buf, ustr_to_str};

#[unsafe(link_section = ".text")]
pub unsafe fn get_proc_address(base_address: *mut u8, symbol: &str) -> Option<usize> {
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


        for i in 0..num_names {
            let name_ptr = (base + names[i] as usize) as *const u8;
            let name = ptr_to_str(name_ptr)?;
            if name == symbol {

                let ordinal = ordinals[i] as usize;
                if ordinal >= funcs.len() {
                    return None;
                }

                let func_rva = funcs[ordinal];
                let func_addr = base + func_rva as usize;

                if func_rva >= export_rva && func_rva < export_rva + export_size {
                    let forwarder_str = ptr_to_str(rva::<u8>(base, func_rva))?;
                    return resolve_forwarder(forwarder_str);
                }

                return Some(func_addr);
            }
        }
        None
    }
}

#[unsafe(link_section = ".text")]
pub unsafe fn load_library(lib: &str) -> Option<*mut u8> {
    unsafe {
        let peb = get_peb();
        let ldr = (*peb).Ldr;
        let list_head = &mut (*ldr).InLoadOrderModuleList as *mut LIST_ENTRY;
        let mut current = (*list_head).flink;

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
                let name = strip_dll_suffix(str_from_buf2);
                if name == lib {
                    return Some((*entry).DllBase as *mut u8);
                }
            }
            current = (*current).flink;
        }
        None
    }
}

#[unsafe(link_section = ".text")]
pub unsafe fn resolve_forwarder(forwarder: &str) -> Option<usize> {
    let idx = forwarder.find('.')?;
    let dll_name_part = &forwarder[..idx];
    let symbol_part = &forwarder[idx + 1..];
    let base = unsafe { load_library(dll_name_part)? };
    if base.is_null() {
        return None;
    }

    unsafe { get_proc_address(base, symbol_part)}

}

pub unsafe fn find_api<T>(base: *mut u8, sym: &str) -> Option<T> {
    unsafe {
        let addr = get_proc_address(base, sym)?;
        Some(core::mem::transmute_copy::<_, T>(&addr))
    }
}