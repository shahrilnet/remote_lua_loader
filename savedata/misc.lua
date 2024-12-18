
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
        local ascii = chunk:gsub('%c', '.') -- replace non-printable characters
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

function sleep(a) 
    local sec = tonumber(os.clock() + a); 
    while (os.clock() < sec) do 
    end 
end

function dump_table(o, depth, indent)
    depth = depth or 2
    indent = indent or 0
    if depth < 1 then return tostring(o) end
    local function get_indent(level)
        return string.rep("  ", level)
    end
    if type(o) == 'table' then
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

function get_module_name(addr)
    local sceKernelGetModuleInfoFromAddr = fcall(libc_addrofs.sceKernelGetModuleInfoFromAddr)
    local buf = memory.alloc(0x100)
    if sceKernelGetModuleInfoFromAddr(addr, 1, buf):tonumber() ~= 0 then
        return nil
    end
    return memory.read_null_terminated_string(buf+8)
end

function resolve_base(initial_addr, modname, max_page_search)

    local initial_page = initial_addr:band(uint64(0xfff):bnot())
    local page_size = 0x1000

    for i=0, max_page_search-1 do
        local base = initial_page - i*page_size
        local cur_modname = get_module_name(base)
        local prev_modname = get_module_name(base - page_size)
        if cur_modname == modname and prev_modname ~= modname then
            return base
        end
    end

    errorf("failed to resolve %s base", modname)
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

function serialize(t)
    local function ser(o)
        if type(o) == "number" then
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