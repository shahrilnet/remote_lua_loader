local socket = require("socket")
local authmgr = require("authmgr")
local sbl = require("sbl")
local self_mod = require("self")
local elf = require("elf")
local memory = require("memory")

local g_kernel_data_base
local g_bump_allocator_base
local g_bump_allocator_cur
local g_bump_allocator_len
local g_dump_queue_buf = nil
local g_dump_queue_buf_pos = 0
local G_DUMP_QUEUE_BUF_SIZE = 1 * 1024 * 1024 -- 1MB


local tailored_offsets = {
    offset_dmpml4i = 0,
    offset_dmpdpi = 0,
    offset_pml4pml4i = 0,
    offset_mailbox_base = 0,
    offset_mailbox_flags = 0,
    offset_mailbox_meta = 0,
    offset_authmgr_handle = 0,
    offset_sbl_sxlock = 0,
    offset_sbl_mb_mtx = 0,
    offset_g_message_id = 0,
    offset_datacave_1 = 0,
    offset_datacave_2 = 0
}
 
local function bump_alloc(len)
    if (g_bump_allocator_cur + len >= (g_bump_allocator_base + g_bump_allocator_len)) then
        return nil
    end
    local ptr = g_bump_allocator_cur
    g_bump_allocator_cur = g_bump_allocator_cur + len

    memory.memset(ptr, 0, len)

    return ptr
end

local function bump_calloc(count, len)
    return bump_alloc(count * len)
end

local function bump_reset()
    g_bump_allocator_cur = g_bump_allocator_base
end

local function sock_print(sock, str)
    if LOG_TO_SOCKET then
        socket.send(sock, str)
    else
        print(str)
    end
end

local function _mkdir(dir)
    local path = ""
    for folder in string.gmatch(dir, "[^/]+") do
        path = path .. "/" .. folder
        os.execute("mkdir -p " .. path)
    end
end


local function get_authmgr_sm(sock, offsets)
    return memory.kernel_copyout(g_kernel_data_base + offsets.offset_authmgr_handle, 8)
end


local function self_verify_header(sock, authmgr_handle, data, size, offsets)
    local data_blob_va = g_kernel_data_base + offsets.offset_datacave_2
    local data_blob_pa = memory.pmap_kextract(sock, data_blob_va)

    memory.kernel_copyin(data, data_blob_va, size)

    local err = authmgr.sceSblAuthMgrSmFinalize(sock, authmgr_handle, 0)
    if err ~= 0 then
        return err
    end

    return authmgr.sceSblAuthMgrVerifyHeader(sock, authmgr_handle, data_blob_pa, size)
end
 
local function self_decrypt_segment(sock, authmgr_handle, service_id, file_data, segment, segment_idx, offsets)
    local err
    local out_segment_data
    local digests = {}
    local block_infos = {}
    local chunk_table = {}
    local chunk_entry = {}

    local data_blob_va = g_kernel_data_base + offsets.offset_datacave_2
    local data_blob_pa = memory.pmap_kextract(sock, data_blob_va)

    if segment.compressed_size < 0x1000 then
        memory.kernel_copyin(file_data:sub(segment.offset + 1, segment.offset + segment.compressed_size), data_blob_va, segment.compressed_size)
    else
        for bytes = 0, segment.compressed_size - 1, 0x1000 do
            local chunk_size = math.min(0x1000, segment.compressed_size - bytes)
            memory.kernel_copyin(file_data:sub(segment.offset + bytes + 1, segment.offset + bytes + chunk_size), data_blob_va + bytes, chunk_size)
        end
    end

    
    chunk_table.first_pa = data_blob_pa
    chunk_table.used_entries = 1
    chunk_table.data_size = segment.compressed_size

    chunk_entry.pa = data_blob_pa
    chunk_entry.size = segment.compressed_size

    local chunk_table_va = g_kernel_data_base + offsets.offset_datacave_1
    local chunk_table_pa = memory.pmap_kextract(sock, chunk_table_va)

    
    memory.kernel_copyin(chunk_table, chunk_table_va, 0x30)

    
    for tries = 1, 3 do
        err = authmgr.sceSblAuthMgrSmLoadSelfSegment(sock, authmgr_handle, service_id, chunk_table_pa, segment_idx)
        if err == 0 then
            break
        end
        os.execute("sleep 1")
    end

    if err ~= 0 then
        return nil
    end

    
    out_segment_data = memory.mmap(nil, segment.uncompressed_size, memory.PROT_READ | memory.PROT_WRITE, memory.MAP_ANONYMOUS | memory.MAP_PRIVATE, -1, 0)
    if out_segment_data == nil then
        return nil
    end

    
    memory.kernel_copyout(data_blob_va, out_segment_data, segment.uncompressed_size)

    
    local segment_info = bump_alloc(16) 
    if segment_info == nil then
        return nil
    end

    segment_info.data = out_segment_data
    segment_info.size = segment.uncompressed_size
    segment_info.block_count = math.ceil(segment.uncompressed_size / self_mod.SELF_SEGMENT_BLOCK_SIZE(segment))

    if self_mod.SELF_SEGMENT_HAS_DIGESTS(segment) then
        local cur_digest = out_segment_data
        for i = 1, segment_info.block_count do
            digests[i] = cur_digest
            cur_digest = cur_digest + 0x20
        end
    end
    segment_info.digests = digests

    for i = 1, segment_info.block_count do
        local block_info = {}
        block_info.offset = (i - 1) * self_mod.SELF_SEGMENT_BLOCK_SIZE(segment)
        if i == segment_info.block_count then
            block_info.len = segment_info.size % self_mod.SELF_SEGMENT_BLOCK_SIZE(segment)
        else
            block_info.len = self_mod.SELF_SEGMENT_BLOCK_SIZE(segment)
        end
        block_infos[i] = block_info
    end
    segment_info.extents = block_infos

    return segment_info
end

function self_decrypt_block(sock, authmgr_handle, service_id, file_data, segment, segment_idx, block_segment, block_idx, offsets)
    local data_blob_va = g_kernel_data_base + offsets.offset_datacave_2
    local data_out_va  = g_kernel_data_base + offsets.offset_datacave_1

    local data_blob_pa = pmap_kextract(sock, data_blob_va)
    local data_out_pa  = pmap_kextract(sock, data_out_va)

    local input_addr = file_data + segment.offset + block_segment.extents[block_idx].offset

    for i = 0, 3 do
        kernel_copyin(input_addr + (i * 0x1000), data_blob_va + (i * 0x1000), 0x1000)
    end

    local err = -1
    for tries = 1, 5 do
        err = _sceSblAuthMgrSmLoadSelfBlock(sock, authmgr_handle, service_id, data_blob_pa, data_out_pa, segment, SELF_SEGMENT_ID(segment), block_segment, block_idx)
        if err == 0 then break end
        usleep(100000)
    end

    if err ~= 0 then
        SOCK_LOG(sock, "[!] failed to decrypt block %d, err: %d\n", block_idx, err)
        return nil
    end

    local out_block_data = mmap(nil, 0x4000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)
    if not out_block_data then return nil end

    
    for i = 0, 3 do
        kernel_copyout(data_out_va + (i * 0x1000), out_block_data + (i * 0x1000), 0x1000)
    end

    return out_block_data
end

function decrypt_self(sock, authmgr_handle, path, out_fd, offsets)
    local err = 0

    
    local self_file_fd = open(path, 0, 0)
    if self_file_fd < 0 then
        SOCK_LOG(sock, "[!] failed to open %s\n", path)
        close(out_fd)
        return self_file_fd
    end

    local self_file_stat = fstat(self_file_fd)
    local self_file_data = mmap(nil, self_file_stat.st_size, PROT_READ, MAP_SHARED, self_file_fd, 0)
    
    if not self_file_data or self_file_data == MAP_FAILED then
        SOCK_LOG(sock, "[!] file mmap failed, reading file instead\n")
        self_file_data = mmap(nil, self_file_stat.st_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)
        
        local total_read = 0
        while total_read < self_file_stat.st_size do
            local read_bytes = read(self_file_fd, self_file_data + total_read, self_file_stat.st_size - total_read)
            if read_bytes <= 0 then
                SOCK_LOG(sock, "[!] failed to read %s\n", path)
                err = -30
                goto cleanup_in_file_data
            end
            total_read = total_read + read_bytes
        end

        SOCK_LOG(sock, "[+] read file into memory\n")
    end

    
    if ffi.cast("uint32_t*", self_file_data)[0] ~= SELF_PROSPERO_MAGIC then
        SOCK_LOG(sock, "[!] %s is not a PS5 SELF file\n", path)
        err = -22
        goto cleanup_in_file_data
    end

    SOCK_LOG(sock, "[+] decrypting %s...\n", path)

    
    local header = ffi.cast("struct sce_self_header*", self_file_data)
    local service_id = self_verify_header(sock, authmgr_handle, self_file_data, header.header_size + header.metadata_size, offsets)

    if service_id < 0 then
        SOCK_LOG(sock, "[!] failed to acquire a service ID\n")
        err = -1
        goto cleanup_in_file_data
    end

    
    local elf_header = ffi.cast("struct elf64_hdr*", self_file_data + sizeof("struct sce_self_header") + (sizeof("struct sce_self_segment_header") * header.segment_count))
    local start_phdrs = ffi.cast("struct elf64_phdr*", elf_header + 1)

    
    local final_file_size = 0
    for i = 0, elf_header.e_phnum - 1 do
        if start_phdrs[i].p_type == PT_NOTE then
            final_file_size = start_phdrs[i].p_offset + start_phdrs[i].p_filesz
        end
    end

    if final_file_size == 0 then
        for i = 0, elf_header.e_phnum - 1 do
            if start_phdrs[i].p_type == PT_LOAD then
                final_file_size = start_phdrs[i].p_offset + start_phdrs[i].p_filesz
            end
        end
    end

    local out_file_data = mmap(nil, final_file_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)
    if not out_file_data then
        err = -12
        goto cleanup_in_file_data
    end

    
    ffi.copy(out_file_data, elf_header, ffi.sizeof("struct elf64_hdr"))
    ffi.copy(out_file_data + ffi.sizeof("struct elf64_hdr"), start_phdrs, elf_header.e_phnum * ffi.sizeof("struct elf64_phdr"))

    
    local block_segments = bump_calloc(header.segment_count, ffi.sizeof("struct self_block_segment*"))
    if not block_segments then
        err = -12
        goto cleanup_out_file_data
    end

    
    for i = 0, header.segment_count - 1 do
        local segment = ffi.cast("struct sce_self_segment_header*", self_file_data + sizeof("struct sce_self_header") + (i * ffi.sizeof("struct sce_self_segment_header")))

        if SELF_SEGMENT_HAS_DIGESTS(segment) then
            SOCK_LOG(sock, "  [?] decrypting block info segment for %d\n", SELF_SEGMENT_ID(segment))
            block_segments[SELF_SEGMENT_ID(segment)] = self_decrypt_segment(sock, authmgr_handle, service_id, self_file_data, segment, SELF_SEGMENT_ID(segment), offsets)

            if not block_segments[SELF_SEGMENT_ID(segment)] then
                SOCK_LOG(sock, "[!] failed to decrypt segment info for %d\n", SELF_SEGMENT_ID(segment))
                err = -11
                goto cleanup_out_file_data
            end
        end
    end

    
    local written_bytes = write(out_fd, out_file_data, final_file_size)
    if written_bytes ~= final_file_size then
        SOCK_LOG(sock, "[!] failed to write decrypted SELF file\n")
        err = -5
    end

    SOCK_LOG(sock, "  [+] wrote %d bytes...\n", written_bytes)

cleanup_out_file_data:
    munmap(out_file_data, final_file_size)
cleanup_in_file_data:
    munmap(self_file_data, self_file_stat.st_size)
    close(self_file_fd)
    close(out_fd)

    bump_reset()

    return err
end

function dump_queue_init(sock)
    if g_dump_queue_buf then
        return 0
    end

    g_dump_queue_buf = memory.mmap(nil, G_DUMP_QUEUE_BUF_SIZE, memory.PROT_READ | memory.PROT_WRITE, memory.MAP_ANONYMOUS | memory.MAP_PRIVATE, -1, 0)
    if not g_dump_queue_buf then
        SOCK_LOG(sock, "[!] failed to allocate buffer for directory entries\n")
        os.exit(-1)
    end

    return 0
end

function dump_queue_reset()
    if not g_dump_queue_buf then
        return 0
    end

    g_dump_queue_buf_pos = 0
    g_dump_queue_buf[0] = '\0'
    return 0
end

function dump_queue_add_file(sock, path)
    dump_queue_init(sock)

    local allowed_exts = { ".elf", ".self", ".prx", ".sprx", ".bin" }
    local len = #path

    --  app0 و patch0
    if len >= 35 and path:sub(1, 20) == "/mnt/sandbox/pfsmnt/" and (path:sub(30, 35) == "-app0/" or path:sub(30, 37) == "-patch0/") then
        return -1
    end

    
    local dot = path:match("^.+(%..+)$")
    if not dot then return -2 end

    local allowed = false
    for _, ext in ipairs(allowed_exts) do
        if dot:lower() == ext then
            allowed = true
            break
        end
    end

    if not allowed then
        return -3
    end

    
    local fd = io.open(path, "rb")
    if not fd then
        SOCK_LOG(sock, "[!] failed to open file: " .. path)
        return -4
    end

    local magic = fd:read(4) -- قراءة أول 4 بايتات
    fd:close()

    if magic ~= SELF_PROSPERO_MAGIC then
        SOCK_LOG(sock, "[!] not a PS5 SELF file: " .. path)
        return -5
    end

    
    local new_g_dump_queue_buf_pos = g_dump_queue_buf_pos + len + 1
    if new_g_dump_queue_buf_pos >= G_DUMP_QUEUE_BUF_SIZE then
        SOCK_LOG(sock, "[!] dump queue buffer full\n")
        os.exit(-2)
    end

    g_dump_queue_buf[g_dump_queue_buf_pos] = path
    g_dump_queue_buf_pos = new_g_dump_queue_buf_pos
    g_dump_queue_buf[g_dump_queue_buf_pos] = '\0'

    return 0
end

function dump_queue_add_dir(sock, path, recursive)
    local dir = io.popen('ls -A "' .. path .. '"')
    if not dir then
        SOCK_LOG(sock, "[!] failed to open directory: " .. path)
        return -1
    end

    for file in dir:lines() do
        local full_path = path .. "/" .. file
        local attr = lfs.attributes(full_path)

        if attr.mode == "file" then
            dump_queue_add_file(sock, full_path)
        elseif recursive and attr.mode == "directory" and file:sub(1, 1) ~= "." then
            dump_queue_add_dir(sock, full_path, recursive)
        end
    end

    dir:close()
    return 0
end

function dump(sock, authmgr_handle, offsets, out_dir_path)
    if not g_dump_queue_buf then
        return -1
    end

    local err = 0
    local sbl_sxlock_addr = g_kernel_data_base + offsets.offset_sbl_sxlock + 0x18
    local spinlock_lock = 0x13371337
    local spinlock_unlock = 0

    kernel_copyout(sbl_sxlock_addr, spinlock_unlock, 8)

    
    for _ = 1, 256 do
        kernel_copyin(spinlock_lock, sbl_sxlock_addr, 8)
        os.execute("sleep 0.001")
    end

    local entry = g_dump_queue_buf
    while entry and entry ~= "" do
        SOCK_LOG(sock, "[+] processing " .. entry)

        local out_file_path = out_dir_path .. entry

        
        local out_fd = io.open(out_file_path, "rb")
        if out_fd then
            local size = out_fd:seek("end")
            out_fd:close()
            if size > 0 then
                SOCK_LOG(sock, "[!] " .. out_file_path .. " already exists, skipping")
                entry = entry:sub(#entry + 2)
                goto continue
            end
        end

        
        local last_slash = out_file_path:match(".*/")
        if last_slash then
            os.execute("mkdir -p " .. last_slash)
        end

        out_fd = io.open(out_file_path, "wb")
        if not out_fd then
            SOCK_LOG(sock, "[!] failed to open " .. out_file_path .. " for writing")
            entry = entry:sub(#entry + 2)
            goto continue
        end

        err = decrypt_self(sock, authmgr_handle, entry, out_fd, offsets)

        if err == -11 then
            
            for _ = 1, 2 do
                out_fd = io.open(out_file_path, "wb")
                err = decrypt_self(sock, authmgr_handle, entry, out_fd, offsets)
                if err == 0 then break end
            end
        end

        if err ~= 0 then
            os.remove(out_file_path)
            SOCK_LOG(sock, "[!] failed to dump " .. entry)
        end

        if err == -5 then
            goto out
        end

        entry = entry:sub(#entry + 2)
        ::continue::
    end

    SOCK_LOG(sock, "[+] done")

::out::
    kernel_copyin(spinlock_unlock, sbl_sxlock_addr, 8)
    return err
end

function main()
    local sock = nil
    local authmgr_handle
    local offsets = {}

    -- LOG_TO_SOCKET
    local function connect_socket()
        local client, err = socket.tcp()
        if not client then return nil end

        client:settimeout(5)
        local success, err = client:connect(PC_IP, PC_PORT)
        if not success then return nil end

        return client
    end

    if LOG_TO_SOCKET then
        sock = connect_socket()
        if not sock then
            return -1
        end
    end

    -- Allocate memory using memory.lua
    g_bump_allocator_len  = 0x100000
    g_bump_allocator_base = memory.mmap(g_bump_allocator_len)

    if not g_bump_allocator_base then
        print("[!] Failed to allocate memory")
        goto out
    end

    g_bump_allocator_cur = g_bump_allocator_base
    g_kernel_data_base = KERNEL_ADDRESS_DATA_BASE

    -- Detect system version
    local version = kernel_get_fw_version() & 0xffff0000
    print(string.format("[+] Firmware version: 0x%x", version))

    -- Firmware offsets mapping
    local fw_offsets = {
        [0x3000000] = {0xC9EE50, 0x2712A98, 0x2712AA0, 0x2712AA8, 0x2CF5F98, 0x2CF5D38, 0x31BE4A0, 0x31BE4A4, 0x31BE1FC, 0x0008000, 0x8720000, 0x8724000},
        [0x3100000] = fw_offsets[0x3000000],
        [0x3200000] = fw_offsets[0x3000000],
        [0x3210000] = fw_offsets[0x3000000],

        [0x4000000] = {0xD0FBB0, 0x2792AB8, 0x2792AC0, 0x2792AC8, 0x2D8DFC0, 0x2D8DD60, 0x3257D00, 0x3257D04, 0x3257A5C, 0x0008000, 0x8720000, 0x8724000},
        [0x4030000] = fw_offsets[0x4000000],
        [0x4500000] = fw_offsets[0x4000000],
        [0x4510000] = fw_offsets[0x4000000],

        [0x5000000] = {0xDEF410, 0x28B3038, 0x28B3040, 0x28B3048, 0x2E9DFC0, 0x2E9DD60, 0x3388D24, 0x3388D28, 0x3387A2C, 0x4260000, 0x8720000, 0x8724000},
        [0x5020000] = fw_offsets[0x5000000],
        [0x5100000] = fw_offsets[0x5000000],

        [0x5500000] = {0xDEF410, 0x28B3038, 0x28B3040, 0x28B3048, 0x2E99FC0, 0x2E99D60, 0x3384D24, 0x3384D28, 0x3383A2C, 0x4260000, 0x8720000, 0x8724000},

        [0x6000000] = {0xE0F8D0, 0x27FF3A8, 0x27FF3B0, 0x27FF3B8, 0x2DE9FC0, 0x2DE9D60, 0x32D45F4, 0x32D45F8, 0x32D32FC, 0x4260000, 0x8720000, 0x8724000},
        [0x6020000] = fw_offsets[0x6000000],
        [0x6500000] = fw_offsets[0x6000000],

        [0x7000000] = {0xE10330, 0x27EF808, 0x27EF810, 0x27EF818, 0x2CBDFC0, 0x2CBDD60, 0x2E1CAE4, 0x2E1CAE8, 0x2E1B79C, 0x4260000, 0x8720000, 0x8724000},
        [0x7010000] = fw_offsets[0x7000000],
        [0x7200000] = fw_offsets[0x7000000],
        [0x7400000] = fw_offsets[0x7000000],
        [0x7600000] = fw_offsets[0x7000000],
        [0x7610000] = fw_offsets[0x7000000]
    }

    if fw_offsets[version] then
        offsets.offset_authmgr_handle, offsets.offset_sbl_mb_mtx, offsets.offset_mailbox_base, offsets.offset_sbl_sxlock,
        offsets.offset_mailbox_flags, offsets.offset_mailbox_meta, offsets.offset_dmpml4i, offsets.offset_dmpdpi,
        offsets.offset_pml4pml4i, offsets.offset_g_message_id, offsets.offset_datacave_1, offsets.offset_datacave_2 = table.unpack(fw_offsets[version])
    else
        print("[!] Unsupported firmware! Dumping and exiting.")
        local dump_buf = {}
        for pg = 0, 0x7800 do
            dump_buf[pg] = memory.copyout(g_kernel_data_base + (pg * 0x1000), 0x1000)
        end

        local dump_fd = io.open("/mnt/usb0/PS5/data_dump.bin", "wb")
        if dump_fd then
            for _, data in ipairs(dump_buf) do
                dump_fd:write(data)
            end
            dump_fd:close()
        end
        print("[+] Dump complete")
        goto out
    end

    -- Initialize SBL offsets
    init_sbl(
        g_kernel_data_base,
        offsets.offset_dmpml4i,
        offsets.offset_dmpdpi,
        offsets.offset_pml4pml4i,
        offsets.offset_mailbox_base,
        offsets.offset_mailbox_flags,
        offsets.offset_mailbox_meta,
        offsets.offset_sbl_mb_mtx,
        offsets.offset_g_message_id
    )

    authmgr_handle = get_authmgr_sm(sock, offsets)
    print(string.format("[+] Auth Manager handle obtained: %d", authmgr_handle))

    -- Dump data
    dump_queue_add_dir(sock, "/mnt/sandbox/pfsmnt", 1)
    dump(sock, authmgr_handle, offsets, "/data/dump")

    ::out::
    if LOG_TO_SOCKET and sock then
        sock:close()
    end
    return 0
end

main()