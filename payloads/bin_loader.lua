function main()
    if PLATFORM ~= "ps4" then
        error("this payload only targets ps4")
    end
    
    check_jailbroken()
    
    -- allocate executable area
    local MAP_COMBINED = bit32.bor(MAP_PRIVATE, MAP_ANONYMOUS)
    local PROT_COMBINED = bit32.bor(PROT_READ, PROT_WRITE, PROT_EXECUTE)

    local ret = syscall.mmap(0, 0x60000, PROT_COMBINED, MAP_COMBINED, -1 ,0)
    if ret:tonumber() < 0 then
        error("mmap() error: " .. get_error_string())
    end

    printf("mmap() allocated at address: 0x%x", ret:tonumber())

    -- read payload from disk
    local payload_path = "/data/payload.bin"
    if not file_exists(payload_path) then
        errorf("file not exist: %s", payload_path)
    end
    
    local st = memory.alloc(120)
    if syscall.stat(payload_path, st):tonumber() < 0 then
        print("Failed getting payload file size")
        return
    end
    local file_size = memory.read_qword(st + 72):tonumber()
    
    local bin_data = file_read(payload_path)
    local bin_data_addr = lua.resolve_value(bin_data)
    printf("File read to address: 0x%x", bin_data_addr:tonumber())

    -- copy payload to executable area
    memory.memcpy(ret:tonumber(), bin_data_addr:tonumber(), file_size)
    printf("First bytes: 0x%x", memory.read_dword(ret:tonumber()):tonumber())

    -- execute payload
    native.fcall(ret:tonumber())
end

main()
