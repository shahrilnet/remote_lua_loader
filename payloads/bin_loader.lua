bin_loader = {}
bin_loader.__index = bin_loader

function bin_loader:load_from_file(filepath)

    if not file_exists(filepath) then
        errorf("file not exist: %s", filepath)
    end

    local self = setmetatable({}, bin_loader)
    
    self.filepath = filepath
    self.bin_data = file_read(filepath)
    self.parse(self)
    
    return self
end

function bin_loader:parse()
    if PLATFORM ~= "ps4" then
        error("this payload only targets ps4")
    end
    
    check_jailbroken()
    
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

    printf("spawning %s", self.filepath)

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

function main()
    local payload_data_path = "/data/payload.bin"
    local payload_savedata_path = string.format("/mnt/sandbox/%s_000/savedata0/payload.bin", get_title_id())

    local existing_path = ""
    if file_exists(payload_data_path) then
        existing_path = payload_data_path
    elseif file_exists(payload_savedata_path) then
        existing_path = payload_savedata_path
    else
        errorf("file not exist: %s", existing_path)
    end
    printf("loading payload from: %s", existing_path)

    local bin = bin_loader:load_from_file(existing_path)
    bin:run()
    bin:wait_for_payload_to_exit()
end

main()
