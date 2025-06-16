
-- rudimentary elf loader
-- only expected to load john tornblom's elfldr.elf

-- credit to nullptr for porting and specter for the original code

elf_loader = {}
elf_loader.__index = elf_loader

elf_loader.shadow_mapping_addr = uint64(0x920100000)
elf_loader.mapping_addr = uint64(0x926100000)

function elf_loader:load_from_file(filepath)

    if not file_exists(filepath) then
        errorf("file not exist: %s", filepath)
    end

    local self = setmetatable({}, elf_loader)
    
    self.filepath = filepath
    self.elf_data = file_read(filepath)
    self.parse(self)
    
    return self
end

function elf_loader:parse()

    -- ELF sizes and offsets
    local SIZE_ELF_HEADER = 0x40
    local SIZE_ELF_PROGRAM_HEADER = 0x38
    local SIZE_ELF_SECTION_HEADER = 0x40

    local OFFSET_ELF_HEADER_ENTRY = 0x18
    local OFFSET_ELF_HEADER_PHOFF = 0x20
    local OFFSET_ELF_HEADER_SHOFF = 0x28
    local OFFSET_ELF_HEADER_PHNUM = 0x38
    local OFFSET_ELF_HEADER_SHNUM = 0x3c

    local OFFSET_PROGRAM_HEADER_TYPE = 0x00
    local OFFSET_PROGRAM_HEADER_FLAGS = 0x04
    local OFFSET_PROGRAM_HEADER_OFFSET = 0x08
    local OFFSET_PROGRAM_HEADER_VADDR = 0x10
    local OFFSET_PROGRAM_HEADER_FILESZ = 0x20
    local OFFSET_PROGRAM_HEADER_MEMSZ = 0x28

    local OFFSET_SECTION_HEADER_TYPE = 0x4
    local OFFSET_SECTION_HEADER_OFFSET = 0x18
    local OFFSET_SECTION_HEADER_SIZE = 0x20

    local OFFSET_RELA_OFFSET = 0x00
    local OFFSET_RELA_INFO = 0x08
    local OFFSET_RELA_ADDEND = 0x10

    local SHT_RELA = 0x4
    local RELA_ENTSIZE = 0x18

    local PF_X = 1

    -- ELF program header types
    local ELF_PT_LOAD = 0x01
    local ELF_PT_DYNAMIC = 0x02

    -- ELF dynamic table types
    local ELF_DT_NULL = 0x00
    local ELF_DT_RELA = 0x07
    local ELF_DT_RELASZ = 0x08
    local ELF_DT_RELAENT = 0x09
    local ELF_R_AMD64_RELATIVE = 0x08

    local elf_store = lua.resolve_value(self.elf_data)

    local elf_entry = memory.read_dword(elf_store + OFFSET_ELF_HEADER_ENTRY):tonumber()
    self.elf_entry_point = elf_loader.mapping_addr + elf_entry

    local elf_program_headers_offset = memory.read_dword(elf_store + OFFSET_ELF_HEADER_PHOFF):tonumber()
    local elf_program_headers_num = memory.read_word(elf_store + OFFSET_ELF_HEADER_PHNUM):tonumber()

    local elf_section_headers_offset = memory.read_dword(elf_store + OFFSET_ELF_HEADER_SHOFF):tonumber()
    local elf_section_headers_num = memory.read_word(elf_store + OFFSET_ELF_HEADER_SHNUM):tonumber()

    local executable_start = 0
    local executable_end = 0

    -- parse program headers
    for i = 0, elf_program_headers_num-1 do

        local phdr_offset = elf_program_headers_offset + (i * SIZE_ELF_PROGRAM_HEADER)
        local p_type = memory.read_dword(elf_store + phdr_offset + OFFSET_PROGRAM_HEADER_TYPE):tonumber()
        local p_flags = memory.read_dword(elf_store + phdr_offset + OFFSET_PROGRAM_HEADER_FLAGS):tonumber()
        local p_offset = memory.read_dword(elf_store + phdr_offset + OFFSET_PROGRAM_HEADER_OFFSET):tonumber()
        local p_vaddr = memory.read_dword(elf_store + phdr_offset + OFFSET_PROGRAM_HEADER_VADDR):tonumber()
        local p_filesz = memory.read_dword(elf_store + phdr_offset + OFFSET_PROGRAM_HEADER_FILESZ):tonumber()
        local p_memsz = memory.read_dword(elf_store + phdr_offset + OFFSET_PROGRAM_HEADER_MEMSZ):tonumber()
        local aligned_memsz = bit32.band(p_memsz + 0x3FFF, 0xFFFFC000)

        if p_type == ELF_PT_LOAD then

            local PROT_RW = bit32.bor(PROT_READ, PROT_WRITE)
            local PROT_RWX = bit32.bor(PROT_READ, PROT_WRITE, PROT_EXECUTE)

            if bit32.band(p_flags, PF_X) == PF_X then

                executable_start = p_vaddr
                executable_end = p_vaddr + p_memsz 

                -- create shm with exec permission
                local exec_handle = syscall.jitshm_create(0, aligned_memsz, 0x7)

                -- create shm alias with write permission
                local write_handle = syscall.jitshm_alias(exec_handle, 0x3)

                -- map shadow mapping and write into it
                syscall.mmap(elf_loader.shadow_mapping_addr, aligned_memsz, PROT_RW, 0x11, write_handle, 0)
                memory.memcpy(elf_loader.shadow_mapping_addr, elf_store + p_offset, p_memsz)

                -- map executable segment
                syscall.mmap(elf_loader.mapping_addr + p_vaddr, aligned_memsz, PROT_RWX, 0x11, exec_handle, 0)
            else
                -- copy regular data segment
                syscall.mmap(elf_loader.mapping_addr + p_vaddr, aligned_memsz, PROT_RW, 0x1012, 0xFFFFFFFF, 0)
                memory.memcpy(elf_loader.mapping_addr + p_vaddr, elf_store + p_offset, p_memsz)
            end
        end
    end

    -- apply relocations
    for i = 0, elf_section_headers_num-1 do

        local shdr_offset = elf_section_headers_offset + (i * SIZE_ELF_SECTION_HEADER)

        local sh_type = memory.read_dword(elf_store + shdr_offset + OFFSET_SECTION_HEADER_TYPE):tonumber()
        local sh_offset = memory.read_qword(elf_store + shdr_offset + OFFSET_SECTION_HEADER_OFFSET):tonumber()
        local sh_size = memory.read_qword(elf_store + shdr_offset + OFFSET_SECTION_HEADER_SIZE):tonumber()

        if sh_type == SHT_RELA then

            local rela_table_count = sh_size / RELA_ENTSIZE

            -- Parse relocs and apply them
            for i = 0, rela_table_count-1 do

                local r_offset = memory.read_qword(elf_store + sh_offset + (i * RELA_ENTSIZE) + OFFSET_RELA_OFFSET):tonumber()
                local r_info = memory.read_qword(elf_store + sh_offset + (i * RELA_ENTSIZE) + OFFSET_RELA_INFO):tonumber()
                local r_addend = memory.read_qword(elf_store + sh_offset + (i * RELA_ENTSIZE) + OFFSET_RELA_ADDEND):tonumber()

                if bit32.band(r_info, 0xFF) == ELF_R_AMD64_RELATIVE then
                    
                    local reloc_addr = elf_loader.mapping_addr + r_offset
                    local reloc_value = elf_loader.mapping_addr + r_addend

                    -- If the relocation falls in the executable section, we need to redirect the write to the
                    -- writable shadow mapping or we'll crash
                    if executable_start <= r_offset and r_offset < executable_end then
                        reloc_addr = elf_loader.shadow_mapping_addr + r_offset
                    end
                
                    memory.write_qword(reloc_addr, reloc_value)
                end
            end
        end
    end

    return

end

function elf_loader:run()

    local Thrd_create = fcall(libc_addrofs.Thrd_create)

    local rwpipe = memory.alloc(8)
    local rwpair = memory.alloc(8)
    local args = memory.alloc(0x30)
    local thr_handle_addr = memory.alloc(8)

    memory.write_dword(rwpipe, ipv6_kernel_rw.data.pipe_read_fd)
    memory.write_dword(rwpipe + 0x4, ipv6_kernel_rw.data.pipe_write_fd)

    memory.write_dword(rwpair, ipv6_kernel_rw.data.master_sock)
    memory.write_dword(rwpair + 0x4, ipv6_kernel_rw.data.victim_sock)

    local syscall_wrapper = dlsym(0x2001, "getpid")

    self.payloadout = memory.alloc(4)

    memory.write_qword(args + 0x00, syscall_wrapper)                -- arg1 = syscall wrapper
    memory.write_qword(args + 0x08, rwpipe)                         -- arg2 = int *rwpipe[2]
    memory.write_qword(args + 0x10, rwpair)                         -- arg3 = int *rwpair[2]
    memory.write_qword(args + 0x18, ipv6_kernel_rw.data.pipe_addr)  -- arg4 = uint64_t kpipe_addr
    memory.write_qword(args + 0x20, kernel.addr.data_base)          -- arg5 = uint64_t kdata_base_addr
    memory.write_qword(args + 0x28, self.payloadout)                -- arg6 = int *payloadout

    printf("spawning %s", self.filepath)

    -- spawn elf in new thread
    local ret = Thrd_create(thr_handle_addr, self.elf_entry_point, args):tonumber()
    if ret ~= 0 then
        error("Thrd_create() error: " .. hex(ret))
    end

    self.thr_handle = memory.read_qword(thr_handle_addr)
end

function elf_loader:wait_for_elf_to_exit()

    local Thrd_join = fcall(libc_addrofs.Thrd_join)

    -- will block until elf terminates
    local ret = Thrd_join(self.thr_handle, 0):tonumber()
    if ret ~= 0 then
        error("Thrd_join() error: " .. hex(ret))
    end

    local out = memory.read_dword(self.payloadout)
    printf("out = %s", hex(out))
end


function main()
    
    if PLATFORM ~= "ps5" then
        error("this payload only targets ps5")
    end

    check_jailbroken()

    syscall.resolve({
        jitshm_create = 0x215,
        jitshm_alias = 0x216,
    })

    run_with_ps5_syscall_enabled(function()
        local elfldr_data_path = "/data/elfldr.elf"
        local elfldr_savedata_path = string.format("/mnt/sandbox/%s_000/savedata0/elfldr.elf", get_title_id())

        local existing_path = ""
        if file_exists(elfldr_data_path) then
            existing_path = elfldr_data_path
        elseif file_exists(elfldr_savedata_path) then
            existing_path = elfldr_savedata_path
        else
            errorf("file not exist: %s", existing_path)
        end
        printf("loading elfldr from: %s", existing_path)

        local elf = elf_loader:load_from_file(existing_path)
        elf:run()
        elf:wait_for_elf_to_exit()
    end)

    print("done")
end

main()

