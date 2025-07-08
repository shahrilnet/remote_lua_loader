-- bin_loader.lua (ELF-aware loader for PS4 toolchain payloads)

bin_loader = {}
bin_loader.__index = bin_loader

-- Constants
local PAGE_SIZE = 0x1000
local MAX_PAYLOAD_SIZE = 4 * 1024 * 1024 -- 4 MB
local PORT = 9020
local READ_CHUNK = 4096
local ELF_MAGIC = "\x7fELF"

-- Helper: round up to nearest page size
local function round_up(x, base)
    return math.floor((x + base - 1) / base) * base
end

-- Read ELF header fields
local function read_elf_header(buffer)
    return {
        e_entry = memory.read_qword(buffer + 0x18):tonumber(),
        e_phoff = memory.read_qword(buffer + 0x20):tonumber(),
        e_phentsize = memory.read_word(buffer + 0x36):tonumber(),
        e_phnum = memory.read_word(buffer + 0x38):tonumber()
    }
end

local function load_elf_segments(buffer, base_addr)
    local elf = read_elf_header(buffer)

    for i = 0, elf.e_phnum - 1 do
        local phdr = buffer + elf.e_phoff + i * elf.e_phentsize
        local p_type = memory.read_dword(phdr + 0x00):tonumber()
        local p_offset = memory.read_qword(phdr + 0x08):tonumber()
        local p_vaddr = memory.read_qword(phdr + 0x10):tonumber()
        local p_filesz = memory.read_qword(phdr + 0x20):tonumber()
        local p_memsz = memory.read_qword(phdr + 0x28):tonumber()

        if p_type == 1 and p_memsz > 0 then -- PT_LOAD
            local seg_addr = base_addr + (p_vaddr % 0x1000000) -- use relative offset
            memory.memcpy(seg_addr, buffer + p_offset, p_filesz)
            if p_memsz > p_filesz then
                -- memory.memset(seg_addr + p_filesz, 0, p_memsz - p_filesz)
            end
        end
    end

    return base_addr + (elf.e_entry % 0x1000000)
end

function bin_loader:load_from_data(data)
    local self = setmetatable({}, bin_loader)
    self.bin_data = data

    local mmap_size = round_up(#self.bin_data, PAGE_SIZE)
    local MAP_COMBINED = bit32.bor(MAP_PRIVATE, MAP_ANONYMOUS)
    local PROT_COMBINED = bit32.bor(PROT_READ, PROT_WRITE, PROT_EXECUTE)

    local ret = syscall.mmap(0, mmap_size, PROT_COMBINED, MAP_COMBINED, -1, 0)
    if ret:tonumber() < 0 then
        error("mmap() error: " .. get_error_string())
    end

    self.mmap_base = ret:tonumber()
    self.mmap_size = mmap_size

    printf("mmap() allocated at: 0x%x", self.mmap_base)

    local buf_addr = lua.resolve_value(self.bin_data):tonumber()

    -- Check ELF magic using raw memory
    local magic = memory.read_dword(buf_addr):tonumber()
    if magic == 0x464c457f then  -- 0x7F 'E' 'L' 'F'
        printf("Detected ELF payload, parsing headers...")
        self.bin_entry_point = load_elf_segments(buf_addr, self.mmap_base)
    else
        printf("Non-ELF payload, treating as raw shellcode")
        memory.memcpy(self.mmap_base, buf_addr, #self.bin_data)
        self.bin_entry_point = self.mmap_base
    end

    printf("Entry point: 0x%x", self.bin_entry_point)
    return self
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

    if syscall.munmap(self.mmap_base, self.mmap_size):tonumber() < 0 then
        error("munmap() error: " .. get_error_string())
    end
end

function listen_for_payload()
    local enable = memory.alloc(4)
    local sockaddr_in = memory.alloc(16)
    local addrlen = memory.alloc(8)
    local buf = memory.alloc(MAX_PAYLOAD_SIZE)

    memory.write_dword(enable, 1)

    local sock_fd = syscall.socket(AF_INET, SOCK_STREAM, 0):tonumber()
    if sock_fd < 0 then
        error("socket() error: " .. get_error_string())
    end

    if syscall.setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, enable, 4):tonumber() < 0 then
        error("setsockopt() error: " .. get_error_string())
    end

    local function htons(port)
        return bit32.bor(bit32.lshift(port, 8), bit32.rshift(port, 8)) % 0x10000
    end

    memory.write_byte(sockaddr_in + 1, AF_INET)
    memory.write_word(sockaddr_in + 2, htons(PORT))
    memory.write_dword(sockaddr_in + 4, INADDR_ANY)

    if syscall.bind(sock_fd, sockaddr_in, 16):tonumber() < 0 then
        error("bind() error: " .. get_error_string())
    end

    if syscall.listen(sock_fd, 3):tonumber() < 0 then
        error("listen() error: " .. get_error_string())
    end

    send_ps_notification(string.format("Listening for a payload on port %d", PORT))
    printf("[+] Listening for a payload on port %d...", PORT)

    memory.write_dword(addrlen, 16)

    local client_fd = syscall.accept(sock_fd, sockaddr_in, addrlen):tonumber()

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
        memory.write_word(sockaddr_in + 2, htons(PORT))
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
        local data = file_read(payload_data_path)
        local bin = bin_loader:load_from_data(data)
        bin:run()
        bin:wait_for_payload_to_exit()
    else
        listen_for_payload()
    end
end

main()
