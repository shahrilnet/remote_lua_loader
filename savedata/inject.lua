
PLATFORM = "ps4"  -- ps4 or ps5
FW_VERSION = nil

options = {
    enable_signal_handler = true,
    run_loader_with_gc_disabled = true,
    run_payload_in_new_thread = true,
}

WRITABLE_PATH = "/av_contents/content_tmp/"
LOG_FILE = WRITABLE_PATH .. "loader_log.txt"
log_fd = io.open(LOG_FILE, "w")

game_name = nil
eboot_base = nil
libc_base = nil
libkernel_base = nil

gadgets = nil
eboot_addrofs = nil
libc_addrofs = nil

native_cmd_handler = nil
native_invoke = nil

old_print = print
function print(...)
    local out = prepare_arguments(...) .. "\n"
    old_print(out)
    log_fd:write(out)
    log_fd:flush()
end

package.path = package.path .. ";/savedata0/?.lua"

require "offsets"
require "misc"
require "bit32"
require "uint64"
require "struct"
require "lua"
require "memory"
require "ropchain"
require "syscall"
require "signal"
require "native"
require "thread"

function run_lua_code(lua_code, client_fd)

    local script, err = loadstring(lua_code)
    if err then
        local err_msg = "error loading script: " .. err
        syscall.write(client_fd, err_msg, #err_msg)
        return
    end

    local env = {
        print = function(...)
            local out = prepare_arguments(...) .. "\n"
            syscall.write(client_fd, out, #out)
        end,
        printf = function(fmt, ...)
            local out = string.format(fmt, ...) .. "\n"
            syscall.write(client_fd, out, #out)
        end,
        client_fd = client_fd,
    }

    setmetatable(env, { __index = _G })
    setfenv(script, env)

    err = run_with_coroutine(script)

    -- pass error to client
    if err then
        syscall.write(client_fd, err, #err)
    end
end

function remote_lua_loader(port)

    assert(port)

    local AF_INET = 2
    local SOCK_STREAM = 1
    local INADDR_ANY = 0

    local SOL_SOCKET = 0xffff  -- options for socket level
    local SO_REUSEADDR = 4  -- allow local address reuse

    local enable = memory.alloc(4)
    local sockaddr_in = memory.alloc(16)
    local addrlen = memory.alloc(8)
    local tmp = memory.alloc(8)

    local maxsize = 500 * 1024  -- 500kb
    local buf = memory.alloc(maxsize)

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
        
        printf("[+] accepted new connection client fd %d", client_fd)

        if size > 0 and size < maxsize then
            
            local cur_size = size
            local cur_buf = buf
            
            while cur_size > 0 do
                local read_size = syscall.read(client_fd, cur_buf, cur_size):tonumber()
                if read_size < 0 then
                    error("read() error: " .. get_error_string())
                end
                cur_buf = cur_buf + read_size
                cur_size = cur_size - read_size
            end
            
            local lua_code = memory.read_buffer(buf, size)

            printf("[+] accepted lua code with size %d (%s)", #lua_code, hex(#lua_code))
            
            if options.enable_signal_handler then
                signal.set_sink_fd(client_fd)
            end

            if options.run_payload_in_new_thread then
                run_lua_code_in_new_thread(lua_code, {
                    client_fd = client_fd,
                    close_socket_after_finished = true,
                })
            else
                run_lua_code(lua_code, client_fd)
                syscall.close(client_fd)
            end
        else
            local err = string.format("error: lua code exceed maxsize " ..
                "(given %s maxsize %s)\n", hex(size), hex(maxsize))
            syscall.write(client_fd, err, #err)
            syscall.close(client_fd)
        end
    end

    syscall.close(sock_fd)
end

function main()

    -- setup limited read & write primitives
    lua.setup_primitives()
    print("[+] lua r/w primitives achieved")

    syscall.init()
    print("[+] syscall initialized")

    native.init()
    print("[+] native handler registered")

    print("[+] arbitrary r/w primitives achieved")

    -- resolve required syscalls for remote lua loader 
    syscall.resolve({
        read = 3,
        write = 4,
        open = 5,
        close = 6,
        accept = 30,
        socket = 97,
        bind = 104,
        setsockopt = 105,
        listen = 106,
        sysctl = 202,
        nanosleep = 240,
        sigaction = 416,
    })

    -- setup signal handler
    if options.enable_signal_handler then
        signal.init()
        print("[+] signal handler registered")
    end

    FW_VERSION = get_version()

    thread.init()

    local run_loader = function()
        local port = 9026
        remote_lua_loader(port)
    end

    if options.run_loader_with_gc_disabled then
        run_nogc(run_loader) -- stable but exhaust memory
    else
        run_loader() -- less stable but doesnt exhaust memory
    end

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