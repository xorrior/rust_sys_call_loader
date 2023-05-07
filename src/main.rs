#![feature(asm)]

use std::arch::asm;
use std::mem;
use std::ffi::CString;

fn main() {
    let array_size = 10;
    let syscall_mmap: usize = 9;
    let syscall_mprotect: usize = 10;
    let syscall_munmap: usize = 11;

    let mut buffer: Vec<u8> = vec![0; array_size];

    // Allocate memory using mmap syscall
    let mmap_ptr: *mut u8 = mmap(
        0 as *mut u8,
        array_size,
        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );

    if mmap_ptr == libc::MAP_FAILED {
        panic!("Memory allocation failed");
    }

    // Write the byte array to the allocated memory
    unsafe {
        libc::memcpy(mmap_ptr as *mut libc::c_void, buffer.as_ptr() as *const libc::c_void, array_size);
    }

    // Cast the address to a function pointer and execute it
    let func_ptr: extern "C" fn() = unsafe { mem::transmute(mmap_ptr) };
    func_ptr();

    // Free the allocated memory using munmap syscall
    munmap(mmap_ptr as *mut libc::c_void, array_size);
}

fn mmap(
    addr: *mut u8,
    length: usize,
    prot: libc::c_int,
    flags: libc::c_int,
    fd: libc::c_int,
    offset: libc::off_t,
) -> *mut u8 {
    let mmap_ptr: *mut u8;

    unsafe {
        asm!(
        "syscall",
        in("rax") 9,
        in("rdi") addr,
        in("rsi") length,
        in("rdx") prot,
        in("r10") flags,
        in("r8") fd,
        in("r9") offset,
        lateout("rax") mmap_ptr,
        );
    }

    mmap_ptr
}

fn munmap(addr: *mut libc::c_void, length: usize) {
    unsafe {
        asm!(
        "syscall",
        in("rax") 11,
        in("rdi") addr,
        in("rsi") length,
        );
    }
}
