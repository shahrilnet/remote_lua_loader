
--[[
    run netcat/socat on the other end to receive the kernel data dump
    1) either through netcat
        $ nc -nlvp 5656 > kernel_data_dump.bin
    2) or through socat
        $ socat -u TCP-LISTEN:5656,reuseaddr OPEN:kernel_data_dump.bin,create,trunc
]]

IP = "192.168.1.2"
PORT = 5656

function htons(port)
    return bit32.bor(bit32.lshift(port, 8), bit32.rshift(port, 8)) % 0x10000
end

function aton(ip)
    local a, b, c, d = ip:match("(%d+).(%d+).(%d+).(%d+)")
    return bit32.bor(bit32.lshift(d, 24), bit32.lshift(c, 16), bit32.lshift(b, 8), a)
end

function find_kdata_base_offset(addr_inside_kdata)

    print("start searching for kdata base...")

    local addr = bit64.band(addr_inside_kdata, bit64.bnot(PAGE_SIZE-1))

    local offset = 0
    while true do

        local n1 = kernel.read_dword(addr-offset):tonumber()
        local n2 = kernel.read_dword(addr-offset+4):tonumber()
        local n3 = kernel.read_dword(addr-offset+8):tonumber()
        local n4 = kernel.read_dword(addr-offset+12):tonumber()

        if n1 == 1 and n2 == 1 and n3 == 0 and n4 == 0 then 
            return addr - offset
        end

        offset = offset + PAGE_SIZE
    end

end

function dump_kdata_over_network(kdata_base)

    local sock_fd = syscall.socket(AF_INET, SOCK_STREAM, 0):tonumber()
    if sock_fd == -1 then
        error("socket() error: " .. get_error_string())
    end

    local sockaddr_in = memory.alloc(16)

    memory.write_byte(sockaddr_in + 1, AF_INET) -- sin_family
    memory.write_word(sockaddr_in + 2, htons(PORT)) -- sin_port
    memory.write_dword(sockaddr_in + 4, aton(IP)) -- sin_addr

    printf("trying to connect to %s:%d", IP, PORT)

    if syscall.connect(sock_fd, sockaddr_in, 16):tonumber() == -1 then
        error("connect() error: " .. get_error_string())
    end

    print("connected sucessfully")

    print("dumping kdata until crashing...")

    local read_size = PAGE_SIZE
    local mem = memory.alloc(read_size)
    
    local MB = 0x100000

    local offset = 0
    while true do

        kernel.copyout(kdata_base + offset, mem, read_size)

        if syscall.write(sock_fd, mem, read_size):tonumber() == -1 then
            error("write() error: " .. get_error_string())
            break
        end

        if offset % (5 * MB) == 0 then
            printf("dumping kernel data: %d mb", offset / MB)
        end

        offset = offset + read_size
    end

end


function main()

    check_kernel_rw()

    if PLATFORM ~= "ps5" then
        error("this payload only targets ps5")
    end

    local kdata_base = kernel.addr.data_base
    
    -- if kdata base is unknown, search for it
    if not kdata_base then
        if not kernel.addr.inside_kdata then
            error("an address inside kdata is needed for dumper to work")
        end
        kdata_base = find_kdata_base_offset(kernel.addr.inside_kdata)
    end

    printf("kdata base: %s", hex(kdata_base))

    dump_kdata_over_network(kdata_base)
end

main()

