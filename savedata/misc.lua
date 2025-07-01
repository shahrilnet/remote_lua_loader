
--
-- misc functions
--

function printf(fmt, ...)
    print(string.format(fmt, ...))
end

function notify(s)
    e:tag{"dialog", title="", message=s}
end

function error(s)
    assert(false, s)
end

function errorf(fmt, ...)
    error(string.format(fmt, ...))
end

function prepare_arguments(...)
    local s = ""
    for i,v in ipairs(arg) do
        s = s .. tostring(v)
        if i < #arg then
            s = s .. "\t"
        end
    end
    return s
end

function file_exists(name)
    local f = io.open(name, "r")
    if f ~= nil then
        io.close(f)
        return true
    else
        return false
    end
 end

function file_write(filename, data, mode)
    local fd = io.open(filename, mode or "wb")
    fd:write(data)
    fd:close()
end

function file_read(filename, mode)
    return io.open(filename, mode):read("*all")
end

function hex_dump(buf, addr)
    addr = addr or 0
    local result = {}
    for i = 1, #buf, 16 do
        local chunk = buf:sub(i, i+15)
        local hexstr = chunk:gsub('.', function(c) 
            return string.format('%02X ', string.byte(c)) 
        end)
        local ascii = chunk:gsub('.', function(c)
            local byte = string.byte(c)
            return (byte >= 32 and byte <= 126) and c or '.'
        end)
        table.insert(result, string.format('%s  %-48s %s', hex(addr+i-1), hexstr, ascii))
    end
    return table.concat(result, '\n')
end

function hex_to_binary(hex)
    return (hex:gsub('..', function(cc)
        return string.char(tonumber(cc, 16))
    end))
end

function bin_to_hex(str)
    return (str:gsub('.', function(c)
        return string.format('%02x', string.byte(c))
    end))
end

function load_bytecode(data)
    local bc, err = loadstring(hex_to_binary(data:gsub("%s+", "")))
    assert(bc, "error while loading bytecode: " .. tostring(err))
    return bc
end

function run_with_coroutine(f)
    local co = coroutine.create(f)
    local ok, result = coroutine.resume(co)
    if not ok then
        local traceback = debug.traceback(co) .. debug.traceback():sub(17)
        return result .. "\n" .. traceback
    end
end

function run_nogc(f)
    collectgarbage("stop")
    f()
    collectgarbage("restart")
end

function dump_table(o, depth, indent)
    depth = depth or 2
    indent = indent or 0
    if depth < 1 then
        return string.format("%q", tostring(o))
    end
    local function get_indent(level)
        return string.rep("  ", level)
    end
    if is_uint64(o) then
        return string.format("%s", hex(o))
    elseif type(o) == 'table' then
        local s = '{\n'
        local inner_indent = indent + 1
        for k, v in pairs(o) do
            s = s .. get_indent(inner_indent)
            if type(k) ~= 'number' then
                k = '"' .. k .. '"'
            end
            s = s .. '[' .. k .. '] = ' .. dump_table(v, depth - 1, inner_indent)
            s = s .. ',\n'
        end
        s = s .. get_indent(indent) .. '}'
        return s
    else
        return tostring(o)
    end
end

function align_to(v,n)
    if is_uint64(v) then
        n = uint64(n)
    end
    return v + (n - v % n) % n
end

function align_16(v)
    return align_to(v, 16)
end

function find_pattern(buffer, pattern)
    local pat = pattern:gsub("%S+", function(b)
        return b == "?" and "." or string.char(tonumber(b, 16))
    end):gsub("%s+", "")
    local matches, start = {}, 1
    while true do
        local s = buffer:find(pat, start)
        if not s then break end
        matches[#matches+1], start = s, s+1
    end
    return matches
end

function get_error_string()
    local strerror = fcall(libc_addrofs.strerror)
    local error_func = fcall(libc_addrofs.error)
    local errno = memory.read_qword(error_func())
    return errno:tonumber() .. " " .. memory.read_null_terminated_string(strerror(errno))
end

function sysctlbyname(name, oldp, oldp_len, newp, newp_len)
    
    local translate_name_mib = memory.alloc(0x8)
    local buf_size = 0x70
    local mib = memory.alloc(buf_size)
    local size = memory.alloc(0x8)

    memory.write_qword(translate_name_mib, 0x300000000)
    memory.write_qword(size, buf_size)
    
    if syscall.sysctl(translate_name_mib, 2, mib, size, name, #name):tonumber() < 0 then
        errorf("failed to translate sysctl name to mib (%s)", name)
    end

    if syscall.sysctl(mib, 2, oldp, oldp_len, newp, newp_len):tonumber() < 0 then
        return false
    end

    return true
end

function get_version()

    local version = nil

    local buf = memory.alloc(0x8)
    local size = memory.alloc(0x8)
    memory.write_qword(size, 0x8)

    if sysctlbyname("kern.sdk_version", buf, size, 0, 0) then
        local ver = memory.read_buffer(buf+2, 2)
        version = string.format('%x.%02x', string.byte(ver:sub(2,2)), string.byte(ver:sub(1,1)))
    end

    return version
end

-- note: unsupported value types are ignored in the result
function serialize(t)
    local function ser(o)
        if type(o) == "number" or type(o) == "boolean" then
            return tostring(o)
        elseif type(o) == "string" then
            return string.format("%q", o)
        elseif is_uint64(o) then
            return string.format("uint64(%q)", hex(o))
        elseif type(o) == "table" then
            local s = "{"
            for k, v in pairs(o) do
                local key
                if type(k) == "string" then
                    key = "[" .. string.format("%q", k) .. "]"
                else
                    key = "[" .. tostring(k) .. "]"
                end
                s = s .. key .. "=" .. ser(v) .. ","
            end
            return s .. "}"
        else
            return "nil"
        end
    end
    return ser(t)
end

function deserialize(s)
    local env = setmetatable({uint64 = uint64}, {__index = _G})
    local f = assert(loadstring("return " .. s, "deserialize", "t", env))
    return f()
end

function to_ns(value, unit)
    unit = unit:lower()
    local conversions = {
        ns = 1,   -- nanoseconds
        us = 1e3, -- microseconds
        ms = 1e6, -- milliseconds
        s  = 1e9, -- seconds
    }
    if conversions[unit] then
        return value * conversions[unit]
    else
        error("unsupported time unit: " .. unit)
    end
end

function nanosleep(nsec)
    local timespec = memory.alloc(0x10)
    memory.write_qword(timespec, math.floor(nsec / 1e9))     -- tv_sec
    memory.write_qword(timespec + 8, nsec % 1e9)             -- tv_nsec
    if syscall.nanosleep(timespec):tonumber() == -1 then
        error("nanosleep() error: " .. get_error_string())
    end
end

function sleep(val, unit)
    unit = unit or 's'
    if native_invoke then
        return nanosleep(to_ns(val, unit))
    else
        if unit ~= 's' then
            error("sleep() only support second if native exec is not available")
        end
        local sec = tonumber(os.clock() + val); 
        while (os.clock() < sec) do end
    end
end

function send_ps_notification(text)

    local notify_buffer_size = 0xc30
    local notify_buffer = memory.alloc(notify_buffer_size)
    local icon_uri = "cxml://psnotification/tex_icon_system"

    -- credits to OSM-Made for this one. @ https://github.com/OSM-Made/PS4-Notify
    memory.write_dword(notify_buffer + 0, 0)                -- type
    memory.write_dword(notify_buffer + 0x28, 0)             -- unk3
    memory.write_dword(notify_buffer + 0x2C, 1)             -- use_icon_image_uri
    memory.write_dword(notify_buffer + 0x10, -1)            -- target_id
    memory.write_buffer(notify_buffer + 0x2D, text)         -- message
    memory.write_buffer(notify_buffer + 0x42D, icon_uri)    -- uri

    local notification_fd = syscall.open("/dev/notification0", O_WRONLY):tonumber()
    if notification_fd < 0 then
        error("open() error: " .. get_error_string())
    end

    syscall.write(notification_fd, notify_buffer, notify_buffer_size)
    syscall.close(notification_fd)
end

function create_pipe()

    local fildes = memory.alloc(0x10)

    if PLATFORM == "ps5" then

        -- HACK: current syscall wrapper that we use in ps5 (gettimeofday) doesn't
        --       handle pipe() return values correctly (rax/rdx). use rop to manually
        --       get the return values

        local chain = ropchain()
        chain:push_syscall(syscall.pipe)
        chain:push_store_rax_into_memory(fildes)
        chain:push_store_rdx_into_memory(fildes + 4)
        chain:restore_through_longjmp()
        chain:execute_through_coroutine()  
    else
        if syscall.pipe(fildes):tonumber() == -1 then
            error("pipe() error: " .. get_error_string())
        end
    end

    local read_fd = memory.read_dword(fildes):tonumber()
    local write_fd = memory.read_dword(fildes+4):tonumber()

    return read_fd, write_fd
end

function map_fixed_address(addr, size)

    syscall.resolve({
        mmap = 477,
    })

    local MAP_COMBINED = bit32.bor(MAP_PRIVATE, MAP_FIXED, MAP_ANONYMOUS)
    local PROT_COMBINED = bit32.bor(PROT_READ, PROT_WRITE)

    local ret = syscall.mmap(addr, size, PROT_COMBINED, MAP_COMBINED, -1 ,0)
    if ret:tonumber() < 0 then
        error("mmap() error: " .. get_error_string())
    end

    return ret
end

function check_memory_access(addr, check_size)

    if not memory.pipe_initialized then
        local read_fd, write_fd = create_pipe()
        memory.pipe_read_fd = read_fd
        memory.pipe_write_fd = write_fd
        memory.pipe_buf = memory.alloc(0x1000)
        memory.pipe_initialized = true 
    end

    check_size = check_size or 1

    local actual_write_size = syscall.write(memory.pipe_write_fd, addr, check_size):tonumber()
    local result = actual_write_size == check_size
    if not result then
        return false
    end

    if actual_write_size > 1 then
        local actual_read_size = syscall.read(memory.pipe_read_fd, memory.pipe_buf, check_size):tonumber()
        if actual_read_size ~= actual_write_size then
            return false
        end
    end

    return result
end

function is_jailbroken()
    local cur_uid = syscall.getuid():tonumber()
    local is_in_sandbox = syscall.is_in_sandbox():tonumber()
    return cur_uid == 0 and is_in_sandbox == 0
end

function check_jailbroken()
    if not is_jailbroken() then
        error("process is not jailbroken")
    end
end

function load_prx(path)

    local handle_out = memory.alloc(0x4)

    if syscall.dynlib_load_prx(path, 0x0, handle_out, 0x0):tonumber() ~= 0x0 then
        error("dynlib_load_prx() error: " .. get_error_string())
    end

    return memory.read_dword(handle_out)
end

function dlsym(handle, sym)

    if PLATFORM == "ps5" and tonumber(FW_VERSION) >= 5 then
        check_jailbroken()
    end
    
    assert(type(sym) == "string")
    
    local addr_out = memory.alloc(0x8)

    if syscall.dlsym(handle, sym, addr_out):tonumber() == -1 then
        error("dlsym() error: " .. get_error_string())
    end

    return memory.read_qword(addr_out)
end

function get_title_id()

    local sceKernelGetAppInfo = fcall(dlsym(LIBKERNEL_HANDLE, "sceKernelGetAppInfo"))

    local app_info = memory.alloc(0x100)
    
    local ret = sceKernelGetAppInfo(syscall.getpid(), app_info):tonumber()
    if ret ~= 0 then
        error("sceKernelGetAppInfo() error: " .. hex(ret))
    end

    return memory.read_null_terminated_string(app_info + 0x10)
end

-- note: this is only for current process
function find_mod_by_name(name)

    local sceKernelGetModuleListInternal = fcall(dlsym(LIBKERNEL_HANDLE, "sceKernelGetModuleListInternal"))
    local sceKernelGetModuleInfo = fcall(dlsym(LIBKERNEL_HANDLE, "sceKernelGetModuleInfo"))

    local mem = memory.alloc(4 * 0x300)
    local actual_num = memory.alloc(8)

    sceKernelGetModuleListInternal(mem, 0x300, actual_num)

    local num = memory.read_qword(actual_num):tonumber()
    for i=0,num-1 do

        local handle = memory.read_dword(mem + i*4)
        local info = memory.alloc(0x160)
        memory.write_qword(info, 0x160)

        sceKernelGetModuleInfo(handle, info)

        local mod_name = memory.read_null_terminated_string(info + 8)
        if name == mod_name then

            local base_addr = memory.read_qword(info + 0x108)
            return {
                handle = handle,
                base_addr = base_addr,
            }
        end
    end

    return nil
end

-- ref: https://github.com/idlesauce/umtx2/blob/71bdf0237b3ce488653cb16699e098d7ddbc3a92/document/en/ps5/main.js#L405
function get_network_interface_addr()

    local count = syscall.netgetiflist(0, 10):tonumber()
    if count == -1 then
        error("netgetiflist() error: " .. get_error_string())
    end

    local iface_size = 0x1e0
    local iface_buf = memory.alloc(iface_size * count)
    
    if syscall.netgetiflist(iface_buf, count):tonumber() == -1 then
        error("netgetiflist() error: " .. get_error_string())
    end

    local iface_list = {}

    for i=0,count-1 do
        local iface_name = memory.read_null_terminated_string(iface_buf + i*iface_size)
        local iface_ip_buf = memory.read_buffer(iface_buf + i*iface_size + 0x28, 4)
        local iface_ip_str = string.format("%d.%d.%d.%d",
            string.byte(iface_ip_buf, 1), string.byte(iface_ip_buf, 2),
            string.byte(iface_ip_buf, 3), string.byte(iface_ip_buf, 4))
        iface_list[iface_name] = iface_ip_str
    end

    return iface_list
end

function get_current_ip()
    local iface_list = get_network_interface_addr()
    for iface_name, iface_ip in pairs(iface_list) do
        if iface_name == "eth0" or iface_name == "wlan0" then
            if iface_ip ~= "0.0.0.0" and iface_ip ~= "127.0.0.1" then
                return iface_ip
            end
        end
    end
end


-- store data that persists across payload executions

storage = {}
storage.data = {}

function storage.set(k, v)
    assert(type(k) == "string")
    storage.data[k] = serialize(v)
end

function storage.get(k)
    if not storage.data[k] then
        return nil        
    end
    return deserialize(storage.data[k])
end

function storage.del(k)
    storage.data[k] = nil
end

function storage.list()
    local out = {}
    table.insert(out, "storage list:")
    for k,v in pairs(storage.data) do
        if #v < 128 then
            table.insert(out, string.format("%s => %s", k, v))
        else
            table.insert(out, string.format("%s => ... (size = %d bytes)", k, #v))
        end
    end
    return table.concat(out, '\n')
end