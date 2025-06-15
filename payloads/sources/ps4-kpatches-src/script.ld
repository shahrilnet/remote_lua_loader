OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)

PHDRS { code_seg PT_LOAD; }

SECTIONS { .text : { *(.text.start) *(.text*) } : code_seg }
