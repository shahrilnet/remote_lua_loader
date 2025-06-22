/* Copyright (C) 2024-2025 anonymous

This file is part of PSFree.

PSFree is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

PSFree is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

// 11.02

#include "types.h"
#include "utils.h"

static inline void do_patch(void *kbase);

__attribute__((section (".text.start")))
int kpatch(void *td) {
    const u64 xfast_syscall_off = 0x1c0;
    void * const kbase = (void *)rdmsr(0xc0000082) - xfast_syscall_off;

    do_patch(kbase);

    return 0;
}

__attribute__((always_inline))
static inline void do_patch(void *kbase) {
    disable_cr0_wp();

    // LightningMods's additional dlsym patches from PPPwn
    write16(kbase, 0x1e4c53, 0x04eb); // skip check 1
    write16(kbase, 0x1e4c63, 0x04eb); // skip check 2
    write16(kbase, 0x1e4c83, 0xe990); // nop + jmp

    // ChendoChap's patches from pOOBs4
    write16(kbase, 0x623f04, 0x00eb); // veriPatch
    write8(kbase, 0xacd, 0xeb); // bcopy
    write8(kbase, 0x2ddd5d, 0xeb); // bzero
    write8(kbase, 0x2ddda1, 0xeb); // pagezero
    write8(kbase, 0x2dde1d, 0xeb); // memcpy
    write8(kbase, 0x2dde61, 0xeb); // pagecopy
    write8(kbase, 0x2dd00d, 0xeb); // copyin
    write8(kbase, 0x2de4bd, 0xeb); // copyinstr
    write8(kbase, 0x2de58d, 0xeb); // copystr

    // stop sysVeri from causing a delayed panic on suspend
    write16(kbase, 0x6247ef, 0x00eb);

    // patch amd64_syscall() to allow calling syscalls everywhere
    // struct syscall_args sa; // initialized already
    // u64 code = get_u64_at_user_address(td->tf_frame-tf_rip);
    // int is_invalid_syscall = 0
    //
    // // check the calling code if it looks like one of the syscall stubs at a
    // // libkernel library and check if the syscall number correponds to the
    // // proper stub
    // if ((code & 0xff0000000000ffff) != 0x890000000000c0c7
    //     || sa.code != (u32)(code >> 0x10)
    // ) {
    //     // patch this to " = 0" instead
    //     is_invalid_syscall = -1;
    // }
    write32(kbase, 0x490, 0);
    // these code corresponds to the check that ensures that the caller's
    // instruction pointer is inside the libkernel library's memory range
    //
    // // patch the check to always go to the "goto do_syscall;" line
    // void *code = td->td_frame->tf_rip;
    // if (libkernel->start <= code && code < libkernel->end
    //     && is_invalid_syscall == 0
    // ) {
    //     goto do_syscall;
    // }
    //
    // do_syscall:
    //     ...
    //     lea     rsi, [rbp - 0x78]
    //     mov     rdi, rbx
    //     mov     rax, qword [rbp - 0x80]
    //     call    qword [rax + 8] ; error = (sa->callp->sy_call)(td, sa->args)
    //
    // sy_call() is the function that will execute the requested syscall.
    write8(kbase, 0x4c2, 0xeb);
    write16(kbase, 0x4b9, 0x00eb);
    write16(kbase, 0x4b5, 0x00eb);

    // patch sys_setuid() to allow freely changing the effective user ID
    // ; PRIV_CRED_SETUID = 50
    // call priv_check_cred(oldcred, PRIV_CRED_SETUID, 0)
    // test eax, eax
    // je ... ; patch je to jmp
    write8(kbase, 0x4314b6, 0xeb);

    // patch vm_map_protect() (called by sys_mprotect()) to allow rwx mappings
    //
    // this check is skipped after the patch
    //
    // if ((new_prot & current->max_protection) != new_prot) {
    //     vm_map_unlock(map);
    //     return (KERN_PROTECTION_FAILURE);
    // }
    write32(kbase, 0x35c90e, 0);

    // TODO: Description of this patch. patch sys_dynlib_load_prx()
    write16(kbase, 0x1e4714, 0xe990);

    // patch sys_dynlib_dlsym() to allow dynamic symbol resolution everywhere
    // call    ...
    // mov     r14, qword [rbp - 0xad0]
    // cmp     eax, 0x4000000
    // jb      ... ; patch jb to jmp
    write32(kbase, 0x1e4cc8, 0x013ce990);
    // patch called function to always return 0
    //
    // sys_dynlib_dlsym:
    //     ...
    //     mov     edi, 0x10 ; 16
    //     call    patched_function ; kernel_base + 0x951c0
    //     test    eax, eax
    //     je      ...
    //     mov     rax, qword [rbp - 0xad8]
    //     ...
    // patched_function: ; patch to "xor eax, eax; ret"
    //     push    rbp
    //     mov     rbp, rsp
    //     ...
    write32(kbase, 0x88ce0, 0xc3c03148);

    // patch sys_mmap() to allow rwx mappings
    // patch maximum cpu mem protection: 0x33 -> 0x37
    // the ps4 added custom protections for their gpu memory accesses
    // GPU X: 0x8 R: 0x10 W: 0x20
    // that's why you see other bits set
    // ref: https://cturt.github.io/ps4-2.html
    write8(kbase, 0x15628a, 0x37);
    write8(kbase, 0x15628d, 0x37);

    // overwrite the entry of syscall 11 (unimplemented) in sysent
    //
    // struct args {
    //     u64 rdi;
    //     u64 rsi;
    //     u64 rdx;
    //     u64 rcx;
    //     u64 r8;
    //     u64 r9;
    // };
    //
    // int sys_kexec(struct thread td, struct args *uap) {
    //     asm("jmp qword ptr [rsi]");
    // }
    const u64 sysent_11_off = 0x1101970;
    // .sy_narg = 2
    write32(kbase, sysent_11_off, 2);
    // .sy_call = gadgets['jmp qword ptr [rsi]']
    write64(kbase, sysent_11_off + 8, kbase + 0x71a21);
    // .sy_thrcnt = SY_THR_STATIC
    write32(kbase, sysent_11_off + 0x2c, 1);

    enable_cr0_wp();
}
