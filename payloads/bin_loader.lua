function main()
    if PLATFORM ~= "ps4" then
        error("this payload only targets ps4")
    end
    
    -- allocate executable area
    local MAP_COMBINED = bit32.bor(MAP_PRIVATE, MAP_ANONYMOUS)
    local PROT_COMBINED = bit32.bor(PROT_READ, PROT_WRITE, PROT_EXECUTE)

    local ret = syscall.mmap(0, 0x10000, PROT_COMBINED, MAP_COMBINED, -1 ,0)
    if ret:tonumber() < 0 then
        error("mmap() error: " .. get_error_string())
    end

    printf("mmap() allocated at address: 0x%x", ret:tonumber())

    -- read payload from disk
    local bin_data = file_read("/av_contents/content_tmp/payload.bin")
    local bin_data_addr = lua.resolve_value(bin_data)
    printf("0x%x", bin_data_addr:tonumber())

    -- copy payload to executable area
    memory.memcpy(ret:tonumber(), bin_data_addr:tonumber(), 0x10000)
    printf("0x%x", memory.read_dword(ret:tonumber()):tonumber())

    -- execute payload
    native.fcall(ret:tonumber())
end

main()
