bin_loader = {}
bin_loader.__index = bin_loader

function bin_loader:load_from_file(filepath)
    local self = setmetatable({}, bin_loader)
    
    self.bin_data = file_read(filepath)
    self.parse(self)
    
    return self
end

function bin_loader:load_from_data(data)
    local self = setmetatable({}, bin_loader)
    
    self.bin_data = data
    self.parse(self)
    
    return self
end

function bin_loader:parse()
    -- allocate executable area
    local MAP_COMBINED = bit32.bor(MAP_PRIVATE, MAP_ANONYMOUS)
    local PROT_COMBINED = bit32.bor(PROT_READ, PROT_WRITE, PROT_EXECUTE)

    local ret = syscall.mmap(0, 0x100000, PROT_COMBINED, MAP_COMBINED, -1 ,0)
    if ret:tonumber() < 0 then
        error("mmap() error: " .. get_error_string())
    end
    
    self.bin_entry_point = ret:tonumber()
    printf("mmap() allocated at address: 0x%x", self.bin_entry_point)
    
    local bin_data_addr = lua.resolve_value(self.bin_data)
    printf("File read to address: 0x%x", bin_data_addr:tonumber())

    -- copy payload to executable area
    memory.memcpy(self.bin_entry_point, bin_data_addr:tonumber(), #self.bin_data)
    printf("First bytes: 0x%x", memory.read_dword(self.bin_entry_point):tonumber())
end

function bin_loader:run()

    local Thrd_create = fcall(libc_addrofs.Thrd_create)

    local thr_handle_addr = memory.alloc(8)

    print("spawning payload")
    send_ps_notification("spawning payload")

    -- spawn elf in new thread
    local ret = Thrd_create(thr_handle_addr, self.bin_entry_point):tonumber()
    if ret ~= 0 then
        error("Thrd_create() error: " .. hex(ret))
    end
self.thr_handle = memory.read_qword(thr_handle_addr)
end

function bin_loader:wait_for_payload_to_exit()

    local Thrd_join = fcall(libc_addrofs.Thrd_join)

    -- will block until elf terminates
    local ret = Thrd_join(self.thr_handle, 0):tonumber()
    if ret ~= 0 then
        error("Thrd_join() error: " .. hex(ret))
    end
    
    if syscall.munmap(self.bin_entry_point, 0x100000):tonumber() < 0 then
        error("munmap() error: " .. get_error_string())
    end
end

function listen_for_payload()

    local port = 9021
    local enable = memory.alloc(4)
    local sockaddr_in = memory.alloc(16)
    local addrlen = memory.alloc(8)
    local tmp = memory.alloc(8)

    local command_magic = 0xffffffff
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

    local function htons(port)
        return bit32.bor(bit32.lshift(port, 8), bit32.rshift(port, 8)) % 0x10000
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

    send_ps_notification(string.format("Listening for a payload on port %s", port))

    print("[+] Listening for a payload on port 9021...")
    
    memory.write_dword(addrlen, 16)

    client_fd = syscall.accept(sock_fd, sockaddr_in, addrlen):tonumber()  
    
    -- need to reinit the socket after rest mode
    while client_fd < 0 do
        print("accept() error: " .. get_error_string())
        
        syscall.close(sock_fd)
        
        sock_fd = syscall.socket(AF_INET, SOCK_STREAM, 0):tonumber()
        if sock_fd < 0 then
            error("socket() error: " .. get_error_string())
        end

        memory.write_dword(enable, 1)
        if syscall.setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, enable, 4):tonumber() < 0 then
            error("setsockopt() error: " .. get_error_string())
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
        
        print("[+] waiting for new connection...")
        
        memory.write_dword(addrlen, 16)

        client_fd = syscall.accept(sock_fd, sockaddr_in, addrlen):tonumber()  
    end
    
    printf("[+] accepted new connection client fd %d", client_fd)

    local cur_buf = buf
    
    local read_size
    repeat
        read_size = syscall.read(client_fd, cur_buf, 4096):tonumber()
        cur_buf = cur_buf + read_size
    until read_size <= 0
    
    local payload_size = cur_buf - buf
    local payload_data = memory.read_buffer(buf, payload_size)

    printf("[+] accepted payload with size %d (%s)", #payload_data, hex(#payload_data))

    local bin = bin_loader:load_from_data(payload_data)
    bin:run()
    bin:wait_for_payload_to_exit()
    
    syscall.close(client_fd)
    client_fd = nil

    syscall.close(sock_fd)
end

function main()
    if PLATFORM ~= "ps4" then
        error("this payload only targets ps4")
    end
    
    check_jailbroken()
    
    if kernel.is_ps4_kpatches_applied == false then
        error("PS4 kernel patches are required but were not applied")
    end
    
    local payload_data_path = "/data/payload.bin"

    if file_exists(payload_data_path) then
        printf("loading payload from: %s", payload_data_path)
        
        local bin = bin_loader:load_from_file(payload_data_path)
        bin:run()
        bin:wait_for_payload_to_exit()
    else
        listen_for_payload()
    end
end

main()
