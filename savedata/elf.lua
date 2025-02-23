local elf = {}


elf.EI_NIDENT = 0x10
elf.PT_LOAD = 0x01
elf.PT_NOTE = 0x04


elf.Elf32_Ehdr = {
    e_ident = {},
    e_type = 0,
    e_machine = 0,
    e_version = 0,
    e_entry = 0,
    e_phoff = 0,
    e_shoff = 0,
    e_flags = 0,
    e_ehsize = 0,
    e_phentsize = 0,
    e_phnum = 0,
    e_shentsize = 0,
    e_shnum = 0,
    e_shstrndx = 0
}


elf.Elf64_Ehdr = {
    e_ident = {},
    e_machine = 0,
    e_version = 0,
    e_entry = 0,
    e_phoff = 0,
    e_shoff = 0,
    e_flags = 0,
    e_ehsize = 0,
    e_phentsize = 0,
    e_phnum = 0,
    e_shentsize = 0,
    e_shnum = 0,
    e_shstrndx = 0
}


elf.Elf32_Phdr = {
    p_type = 0,
    p_offset = 0,
    p_vaddr = 0,
    p_paddr = 0,
    p_filesz = 0,
    p_memsz = 0,
    p_flags = 0,
    p_align = 0
}


elf.Elf64_Phdr = {
    p_type = 0,
    p_flags = 0,
    p_offset = 0,
    p_vaddr = 0,
    p_paddr = 0,
    p_filesz = 0,
    p_memsz = 0,
    p_align = 0 
}

return elf