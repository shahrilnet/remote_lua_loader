
function test_print()

    local lua_code = [[

        function main()

            syscall.resolve({
                thr_self = 432
            })

            local tid = memory.alloc(8)
            syscall.thr_self(tid)
            tid = memory.read_qword(tid)

            print()
            print("hello world from thread!")
            print("thread id: " .. hex(tid))
        end

        main()
    ]]

    local thr = run_lua_code_in_new_thread(lua_code, {
        client_fd = client_fd
    })
    thr:join()
end

function test_syntax_error()
    local thr = run_lua_code_in_new_thread("`", {
        client_fd = client_fd
    })
    thr:join()
end

function test_runtime_error()

    local lua_code = [[
        tbl.notexist()
    ]]

    local thr = run_lua_code_in_new_thread(lua_code, {
        client_fd = client_fd
    })
    thr:join()
end

function test_write_from_thread()

    local mem = memory.alloc(8)
    memory.write_qword(mem, 0xdead)
    
    local lua_code = [[

        function main()
            sleep(5)
            memory.write_qword(args.addr, 0x1337)
        end

        main()
    ]]

    local thr = run_lua_code_in_new_thread(lua_code, {
        client_fd = client_fd,
        args = {
            addr = mem  
        }
    })
    
    print()
    print("before write from new thread: " .. hex(memory.read_qword(mem)))
    print("sleeping for few seconds before checking again...")
    sleep(6)
    print("after write from new thread: " .. hex(memory.read_qword(mem)))
end

function main()
    test_print()
    -- test_syntax_error()
    -- test_runtime_error()
    test_write_from_thread()
end

main()