/* Copyright (C) 2024 anonymous

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

#ifndef UTILS_H_
#define UTILS_H_

#include "types.h"

static inline u64 rdmsr(u32 msr) {
    u32 low;
    u32 high;

    asm("rdmsr" : "=a" (low), "=d" (high) : "c" (msr));
    return (low | ((u64)high << 32));
}

static inline void enable_cr0_wp(void) {
    asm(
        "mov rax, cr0\n"
        "or rax, 0x10000\n"
        "mov cr0, rax\n"
    ::: "rax");
}

static inline void disable_cr0_wp(void) {
    asm(
        "mov rax, cr0\n"
        "and rax, ~0x10000\n"
        "mov cr0, rax\n"
    ::: "rax");
}

static inline void write8(void *addr, u64 offset, u8 value) {
    *(u8 *)(addr + offset) = value;
}

static inline void write16(void *addr, u64 offset, u16 value) {
    *(u16 *)(addr + offset) = value;
}

static inline void write32(void *addr, u64 offset, u32 value) {
    *(u32 *)(addr + offset) = value;
}

static inline void write64(void *addr, u64 offset, u64 value) {
    *(u64 *)(addr + offset) = value;
}

#endif
