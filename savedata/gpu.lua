
-- credit to flatz and shadPS4 project for references

-- gpu page table

GPU_PDE_SHIFT = {
    VALID = 0,
    IS_PTE = 54,
    TF = 56,
    BLOCK_FRAGMENT_SIZE = 59,
}

GPU_PDE_MASKS = {
    VALID = 1,
    IS_PTE = 1,
    TF = 1,
    BLOCK_FRAGMENT_SIZE = 0x1f,
}

GPU_PDE_ADDR_MASK = uint64("0x0000ffffffffffc0")

function gpu_pde_field(pde, field)
    local shift = GPU_PDE_SHIFT[field]
    local mask = GPU_PDE_MASKS[field]
    return bit64.band(bit64.rshift(pde, shift), mask):tonumber()
end

function gpu_walk_pt(vmid, virt_addr)

    local pdb2_addr = get_pdb2_addr(vmid)

    local pml4e_index = bit64.band(bit64.rshift(virt_addr, 39), 0x1ff)
    local pdpe_index = bit64.band(bit64.rshift(virt_addr, 30), 0x1ff)
    local pde_index = bit64.band(bit64.rshift(virt_addr, 21), 0x1ff)

    -- PDB2

    local pml4e = kernel.read_qword(pdb2_addr + pml4e_index * 8)

    if gpu_pde_field(pml4e, "VALID") ~= 1 then
        return nil
    end

    -- PDB1

    local pdp_base_pa = bit64.band(pml4e, GPU_PDE_ADDR_MASK)
    local pdpe_va = phys_to_dmap(pdp_base_pa) + pdpe_index * 8
    local pdpe = kernel.read_qword(pdpe_va)

    if gpu_pde_field(pdpe, "VALID") ~= 1 then
        return nil
    end

    -- PDB0

    local pd_base_pa = bit64.band(pdpe, GPU_PDE_ADDR_MASK)
    local pde_va = phys_to_dmap(pd_base_pa) + pde_index * 8
    local pde = kernel.read_qword(pde_va)

    if gpu_pde_field(pde, "VALID") ~= 1 then
        return nil
    end

    if gpu_pde_field(pde, "IS_PTE") == 1 then
        return pde_va, 0x200000  -- 2mb 
    end

    -- PTB

    local fragment_size = gpu_pde_field(pde, "BLOCK_FRAGMENT_SIZE")
    local offset = bit64.band(virt_addr, 0x1fffff)
    local pt_base_pa = bit64.band(pde, GPU_PDE_ADDR_MASK)

    local pte_index, pte
    local pte_va, page_size
    
    if fragment_size == 4 then
        pte_index = bit64.rshift(offset, 16)
        pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8
        pte = kernel.read_qword(pte_va)

        if gpu_pde_field(pte, "VALID") == 1 and gpu_pde_field(pte, "TF") == 1 then
            pte_index = bit64.rshift(bit64.band(virt_addr, 0xffff), 13)
            pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8
            page_size = 0x2000 -- 8kb
        else
            page_size = 0x10000 -- 64kb
        end

    elseif fragment_size == 1 then
        pte_index = bit64.rshift(offset, 13)
        pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8
        page_size = 0x2000 -- 8kb
    end

    return pte_va, page_size
end





-- kernel r/w primitives based on GPU DMA

gpu = {}

gpu.dmem_size = 2 * 0x100000 -- 2mb

function gpu.setup()

    check_kernel_rw()

    local libSceGnmDriver = find_mod_by_name("libSceGnmDriverForNeoMode.sprx")

    -- put these into global to make life easier
    sceKernelAllocateMainDirectMemory = fcall(dlsym(LIBKERNEL_HANDLE, "sceKernelAllocateMainDirectMemory"))
    sceKernelMapDirectMemory = fcall(dlsym(LIBKERNEL_HANDLE, "sceKernelMapDirectMemory"))
    sceGnmSubmitCommandBuffers = fcall(dlsym(libSceGnmDriver.handle, "sceGnmSubmitCommandBuffers"))
    sceGnmSubmitDone = fcall(dlsym(libSceGnmDriver.handle, "sceGnmSubmitDone"))

    local prot_ro = bit32.bor(PROT_READ, PROT_WRITE, GPU_READ)
    local prot_rw = bit32.bor(prot_ro, GPU_WRITE)

    local victim_va = alloc_main_dmem(gpu.dmem_size, prot_rw, MAP_NO_COALESCE) 
    local transfer_va = alloc_main_dmem(gpu.dmem_size, prot_rw, MAP_NO_COALESCE)
    local cmd_va = alloc_main_dmem(gpu.dmem_size, prot_rw, MAP_NO_COALESCE)

    local curproc_cr3 = get_proc_cr3(kernel.addr.curproc)
    local victim_real_pa = virt_to_phys(victim_va, curproc_cr3)

    local victim_ptbe_va, page_size = get_ptb_entry_of_relative_va(victim_va)

    if not victim_ptbe_va or page_size ~= gpu.dmem_size then
        error("failed to setup gpu primitives")
    end

    if syscall.mprotect(victim_va, gpu.dmem_size, prot_ro):tonumber() == -1 then
        error("mprotect() error: " .. get_error_string())
    end

    local initial_victim_ptbe_for_ro = kernel.read_qword(victim_ptbe_va)
    local cleared_victim_ptbe_for_ro = bit64.band(initial_victim_ptbe_for_ro, bit64.bnot(victim_real_pa))

    -- printf("victim va %s real pa %s", hex(victim_va), hex(victim_real_pa))
    -- printf("ptb entry %s page size %s", hex(victim_ptbe_va), hex(page_size))    
    -- printf("ptbe RO. initial %s cleared %s", hex(initial_victim_ptbe_for_ro), hex(cleared_victim_ptbe_for_ro))

    gpu.victim_va = victim_va
    gpu.transfer_va = transfer_va
    gpu.cmd_va = cmd_va
    gpu.victim_ptbe_va = victim_ptbe_va
    gpu.cleared_victim_ptbe_for_ro = cleared_victim_ptbe_for_ro
end

function gpu.pm4_type3_header(opcode, count)
    
    assert(type(opcode) == "number")
    assert(type(count) == "number")

    local packet_type = 3
    local shader_type = 1   -- computer shader
    local predicate = 0     -- predicate disable
    
    return bit32.bor(
        bit32.band(predicate, 0x0),                      -- Predicated version of packet when set
        bit32.lshift(bit32.band(shader_type, 0x1), 1),   -- 0: Graphics, 1: Compute Shader
        bit32.lshift(bit32.band(opcode, 0xff), 8),       -- IT opcode
        bit32.lshift(bit32.band(count - 1, 0x3fff), 16), -- Number of DWORDs - 1 in the information body
        bit32.lshift(bit32.band(packet_type, 0x3), 30)   -- Packet identifier. It should be 3 for type 3 packets
    )
end

function gpu.pm4_dma_data(dest_va, src_va, length)

    local count = 6
    local bufsize = 4 * (count + 1)
    local opcode = 0x50
    local command_len = bit32.band(length, 0x1fffff)

    local pm4 = memory.alloc(bufsize)
    local dma_data_header = bit32.bor(
        bit32.band(0, 0x1),                    -- engine
        bit32.lshift(bit32.band(0, 0x1), 12),  -- src_atc
        bit32.lshift(bit32.band(2, 0x3), 13),  -- src_cache_policy
        bit32.lshift(bit32.band(1, 0x1), 15),  -- src_volatile
        bit32.lshift(bit32.band(0, 0x3), 20),  -- dst_sel (DmaDataDst enum)
        bit32.lshift(bit32.band(0, 0x1), 24),  -- dst_atc
        bit32.lshift(bit32.band(2, 0x3), 25),  -- dst_cache_policy
        bit32.lshift(bit32.band(1, 0x1), 27),  -- dst_volatile
        bit32.lshift(bit32.band(0, 0x3), 29),  -- src_sel (DmaDataSrc enum)
        bit32.lshift(bit32.band(1, 0x1), 31)   -- cp_sync
    )

    memory.write_dword(pm4, gpu.pm4_type3_header(opcode, count)) -- pm4 header
    memory.write_dword(pm4 + 0x4, dma_data_header) -- dma data header (copy: mem -> mem)
    memory.write_dword(pm4 + 0x8, src_va.l)
    memory.write_dword(pm4 + 0xc, src_va.h)
    memory.write_dword(pm4 + 0x10, dest_va.l)
    memory.write_dword(pm4 + 0x14, dest_va.h)
    memory.write_dword(pm4 + 0x18, command_len)

    return memory.read_buffer(pm4, bufsize)
end

function gpu.submit_dma_data_command(dest_va, src_va, size)

    local dcb_count = 1
    local dcb_gpu_addr = memory.alloc(dcb_count * 0x8)
    local dcb_sizes_in_bytes = memory.alloc(dcb_count * 0x4)

    -- prep command buf
    local dma_data = gpu.pm4_dma_data(dest_va, src_va, size)
    memory.write_buffer(gpu.cmd_va, dma_data) -- prep dma cmd

    -- prep param
    memory.write_qword(dcb_gpu_addr, gpu.cmd_va)
    memory.write_dword(dcb_sizes_in_bytes, #dma_data)

    -- submit to gpu
    local ret = sceGnmSubmitCommandBuffers(dcb_count, dcb_gpu_addr, dcb_sizes_in_bytes, 0, 0):tonumber()
    if ret ~= 0 then
        errorf("sceGnmSubmitCommandBuffers() error: %s", hex(ret))
    end

    -- sleep for a while
    -- sleep(1)

    -- inform gpu that current submission is done
    ret = sceGnmSubmitDone():tonumber()
    if ret ~= 0 then
        errorf("sceGnmSubmitDone() error: %s", hex(ret))
    end
end

function gpu.transfer_physical_buffer(phys_addr, size, is_write)

    local trunc_phys_addr = bit64.band(phys_addr, bit64.bnot(gpu.dmem_size - 1))
    local offset = phys_addr - trunc_phys_addr

    if (offset:tonumber() + size > gpu.dmem_size) then
        error("error: trying to write more than direct memory size: " .. size)
    end

    local prot_ro = bit32.bor(PROT_READ, PROT_WRITE, GPU_READ)
    local prot_rw = bit32.bor(prot_ro, GPU_WRITE)
    
    -- remap PTD

    if syscall.mprotect(gpu.victim_va, gpu.dmem_size, prot_ro):tonumber() == -1 then
        error("mprotect() error: " .. get_error_string())
    end

    local new_ptb = bit64.bor(gpu.cleared_victim_ptbe_for_ro, trunc_phys_addr)
    kernel.write_qword(gpu.victim_ptbe_va, new_ptb)

    if syscall.mprotect(gpu.victim_va, gpu.dmem_size, prot_rw):tonumber() == -1 then
        error("mprotect() error: " .. get_error_string())
    end

    local src, dst

    if is_write then
        src = gpu.transfer_va
        dst = gpu.victim_va + offset
    else
        src = gpu.victim_va + offset
        dst = gpu.transfer_va
    end

    -- do the DMA operation
    gpu.submit_dma_data_command(dst, src, size)
end

function gpu.read_buffer(addr, size)

    local phys_addr = virt_to_phys(addr, kernel.addr.kernel_cr3)
    if not phys_addr then
        errorf("failed to translate %s to physical addr", hex(addr))
    end

    gpu.transfer_physical_buffer(phys_addr, size, false)
    return memory.read_buffer(gpu.transfer_va, size)
end

function gpu.write_buffer(addr, buf)

    local phys_addr = virt_to_phys(addr, kernel.addr.kernel_cr3)
    if not phys_addr then
        errorf("failed to translate %s to physical addr", hex(addr))
    end

    memory.write_buffer(gpu.transfer_va, buf) -- prepare data for write
    gpu.transfer_physical_buffer(phys_addr, #buf, true)
end

function gpu.read_byte(kaddr)
    local value = gpu.read_buffer(kaddr, 1)
    return value and #value == 1 and uint64.unpack(value) or nil 
end

function gpu.read_word(kaddr)
    local value = gpu.read_buffer(kaddr, 2)
    return value and #value == 2 and uint64.unpack(value) or nil 
end

function gpu.read_dword(kaddr)
    local value = gpu.read_buffer(kaddr, 4)
    return value and #value == 4 and uint64.unpack(value) or nil 
end

function gpu.read_qword(kaddr)
    local value = gpu.read_buffer(kaddr, 8)
    return value and #value == 8 and uint64.unpack(value) or nil 
end

function gpu.hex_dump(kaddr, size)
    size = size or 0x40
    return hex_dump(gpu.read_buffer(kaddr, size), kaddr)
end

function gpu.write_byte(dest, value)
    gpu.write_buffer(dest, ub8(value):sub(1,1))
end

function gpu.write_word(dest, value)
    gpu.write_buffer(dest, ub8(value):sub(1,2))
end

function gpu.write_dword(dest, value)
    gpu.write_buffer(dest, ub8(value):sub(1,4))
end

function gpu.write_qword(dest, value)
    gpu.write_buffer(dest, ub8(value):sub(1,8))
end






-- misc fns

function alloc_main_dmem(size, prot, flag)

    assert(size and prot)

    local out = memory.alloc(0x8)
    local mem_type = 1 -- 1-10

    local ret = sceKernelAllocateMainDirectMemory(size, size, mem_type, out):tonumber()
    if ret ~= 0 then
        errorf("sceKernelAllocateMainDirectMemory() error %s", hex(ret))
    end

    local phys_addr = memory.read_qword(out)

    memory.write_qword(out, 0)

    local ret = sceKernelMapDirectMemory(out, size, prot, flag, phys_addr, size):tonumber()
    if ret ~= 0 then
        errorf("sceKernelMapDirectMemory() error %s", hex(ret))
    end

    local virt_addr = memory.read_qword(out)
    return virt_addr, phys_addr
end

function get_curproc_vmid()
    local vmspace = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_VM_SPACE)
    local vmid = kernel.read_dword(vmspace + kernel_offset.VMSPACE_VM_VMID)
    return vmid:tonumber()
end

function get_gvmspace(vmid)
    assert(vmid)
    local gvmspace_base = kernel.addr.data_base + kernel_offset.DATA_BASE_GVMSPACE
    return gvmspace_base + vmid * kernel_offset.SIZEOF_GVMSPACE
end

function get_pdb2_addr(vmid)
    local gvmspace = get_gvmspace(vmid)
    return kernel.read_qword(gvmspace + kernel_offset.GVMSPACE_PAGE_DIR_VA)
end

function get_relative_va(vmid, va)

    assert(is_uint64(va))

    local gvmspace = get_gvmspace(vmid)

    local size = kernel.read_qword(gvmspace + kernel_offset.GVMSPACE_SIZE)
    local start_addr = kernel.read_qword(gvmspace + kernel_offset.GVMSPACE_START_VA)
    local end_addr = start_addr + size

    if va >= start_addr and va < end_addr then
        return va - start_addr
    end

    return nil
end

function get_ptb_entry_of_relative_va(virt_addr)

    local vmid = get_curproc_vmid()
    local relative_va = get_relative_va(vmid, virt_addr)

    if not relative_va then
        errorf("invalid virtual addr %s for vmid %d", hex(virt_addr), vmid)
    end

    return gpu_walk_pt(vmid, relative_va)
end
