-- @egycnq

function get_kernel_elf_size()
    -- ELF header offsets
    local E_PHNUM_OFFSET = 0x38  -- Number of program headers
    local E_PHOFF_OFFSET = 0x40  -- Program header offset (should be 0x40)
    
    -- Program header entry size
    local PHDR_SIZE = 0x38
    
    -- Program types
    local PT_LOAD = 1
    local PT_SCE_RELRO = 0x61000000
    
    -- Read number of program headers
    local e_phnum = kernel.read_word(kernel.addr.data_base + E_PHNUM_OFFSET):tonumber()
    printf("Number of program headers: %d", e_phnum)
    
    local end_addr = kernel.addr.data_base:tonumber()  -- Convert kbase to number for comparison
    
    -- Parse each program header
    for i = 0, e_phnum - 1 do
        local phdr_offset = E_PHOFF_OFFSET + (i * PHDR_SIZE)
        
        -- Read p_type (4 bytes at offset 0x00)
        local p_type = kernel.read_dword(kernel.addr.data_base + phdr_offset):tonumber()
        
        -- Only process PT_LOAD and PT_SCE_RELRO segments
        if p_type == PT_LOAD or p_type == PT_SCE_RELRO then
            -- Read segment details and convert to numbers
            local p_vaddr = kernel.read_qword(kernel.addr.data_base + phdr_offset + 0x10):tonumber()
            local p_memsz = kernel.read_qword(kernel.addr.data_base + phdr_offset + 0x28):tonumber()
            local p_align = kernel.read_qword(kernel.addr.data_base + phdr_offset + 0x30):tonumber()
            
            -- Calculate aligned end address
            local segment_end = p_vaddr + p_memsz
            
            -- Apply alignment (next_multiple_of)
            if p_align > 0 then
                local remainder = segment_end % p_align
                if remainder ~= 0 then
                    segment_end = segment_end + (p_align - remainder)
                end
            end
            
            -- Update max end address
            if segment_end > end_addr then
                end_addr = segment_end
                printf("Segment %d: type=0x%X, vaddr=0x%X, size=0x%X, end=0x%X", 
                    i, p_type, p_vaddr, p_memsz, segment_end)
            end
        end
    end
    
    -- Calculate total size
    local total_size = end_addr - kernel.addr.data_base:tonumber()
    printf("Kernel size: 0x%X", total_size)
    return total_size
end

function dump_kernel_elf()
    -- Constants
    local CHUNK_SIZE = 0x4000              -- 16KB chunks
    local PROGRESS_INTERVAL = 0x500000     -- Progress update every 5MB
    local NOTIFICATION_INTERVAL = 10       -- Notification every 10 seconds
    local OUTPUT_PATH = "/mnt/usb0/kernel.elf"
    local FILE_PERMISSIONS = tonumber("0777", 8)
    local BYTES_PER_MB = 1048576
    local BYTES_PER_KB = 1024
    
    -- File flags
    local O_WRONLY = 0x0001
    local O_CREAT = 0x0200
    local O_TRUNC = 0x0400
    
    local fd = nil  -- Track file descriptor for cleanup
    
    -- Send start notification
    send_ps_notification("Starting kernel dump...")
    
    -- Input validation
    if not kernel.addr.data_base or kernel.addr.data_base == 0 then
        local error_msg = "Invalid kernel base address"
        print(error_msg)
        send_ps_notification(error_msg)
        return false
    end
    
    -- Resolve necessary syscalls
    local ok, err = pcall(function()
        syscall.resolve({
            open = 5,
            write = 4,
            close = 6,
            fsync = 95
        })
    end)
    
    if not ok then
        local error_msg = "Failed to resolve syscalls: " .. tostring(err)
        print(error_msg)
        send_ps_notification(error_msg)
        return false
    end
    
    -- Get kernel size
    local kernel_size = get_kernel_elf_size()
    if not kernel_size or kernel_size <= 0 then
        local error_msg = "Invalid kernel size"
        print(error_msg)
        send_ps_notification(error_msg)
        return false
    end
    
    -- Open output file
    print("Opening " .. OUTPUT_PATH)
    local fd_result = syscall.open(OUTPUT_PATH, bit32.bor(O_WRONLY, O_CREAT, O_TRUNC), FILE_PERMISSIONS)
    
    if not fd_result then
        local error_msg = "Failed to call open syscall"
        print(error_msg)
        send_ps_notification(error_msg)
        return false
    end
    
    fd = fd_result:tonumber()
    if fd < 0 then
        local error_msg = "Failed to open USB! Check if USB is inserted"
        print(error_msg)
        send_ps_notification(error_msg)
        return false
    end
    
    -- Calculate size in MB and start dumping
    local size_mb = math.floor(kernel_size / BYTES_PER_MB)
    send_ps_notification(string.format("Dumping %d MB kernel...", size_mb))
    
    print("Dumping kernel to " .. OUTPUT_PATH)
    printf("Total size to dump: 0x%X bytes (%d MB)", kernel_size, size_mb)
    
    -- Dump in chunks
    local offset = 0
    local start_time = os.clock()
    local last_notification_time = start_time
    local dump_success = false
    
    while offset < kernel_size do
        -- Calculate how much to read
        local to_read = math.min(CHUNK_SIZE, kernel_size - offset)
        
        -- Read from kernel memory
        local read_ok, data = pcall(function()
            local read_addr = kernel.addr.data_base + offset
            return kernel.read_buffer(read_addr, to_read)
        end)
        
        if not read_ok or not data then
            local error_msg = string.format("Kernel read failed at offset 0x%X: %s", offset, tostring(data))
            print(error_msg)
            send_ps_notification("Kernel read failed!")
            break
        end
        
        -- Write the data to file
        local write_result = syscall.write(fd, data, #data)
        if not write_result then
            local error_msg = "Write syscall failed"
            print(error_msg)
            send_ps_notification(error_msg)
            break
        end
        
        local written = write_result:tonumber()
        
        if written < 0 then
            local error_msg = "Write failed: " .. get_error_string()
            print(error_msg)
            send_ps_notification(error_msg)
            break
        end
        
        if written == 0 then
            local error_msg = "USB full! Free up space"
            print(error_msg)
            send_ps_notification(error_msg)
            break
        end
        
        offset = offset + written
        
        -- Progress update
        if offset % PROGRESS_INTERVAL == 0 or offset == kernel_size then
            local progress_pct = math.floor((offset * 100) / kernel_size)
            local elapsed = os.clock() - start_time
            local speed_kbps = math.floor(offset / BYTES_PER_KB / elapsed)
            
            printf("Progress: 0x%X / 0x%X (%d%%) - Speed: %d KB/s", 
                offset, kernel_size, progress_pct, speed_kbps)
            
            -- Send notification every NOTIFICATION_INTERVAL seconds
            local current_time = os.clock()
            if current_time - last_notification_time > NOTIFICATION_INTERVAL then
                send_ps_notification(string.format("Dumping... %d%%", progress_pct))
                last_notification_time = current_time
            end
        end
    end
    
    -- Check if we completed successfully
    dump_success = (offset == kernel_size)
    
    if dump_success then
        -- Sync to ensure all data is written
        print("Syncing data to disk...")
        local sync_result = syscall.fsync(fd)
        local sync_ok = sync_result and sync_result:tonumber() >= 0
        
        if not sync_ok then
            print("Warning: fsync failed - data might not be fully written")
            send_ps_notification("Warning: sync failed!")
        end
        
        -- Final stats
        local total_time = os.clock() - start_time
        local avg_speed_kbps = math.floor(offset / BYTES_PER_KB / total_time)
        
        printf("Dump completed in %d seconds", math.floor(total_time))
        printf("Successfully dumped 0x%X bytes (%d MB)", offset, math.floor(offset / BYTES_PER_MB))
        printf("Average speed: %d KB/s", avg_speed_kbps)
        
        -- Send completion notification with formatted time
        local completion_msg
        if total_time < 60 then
            completion_msg = string.format("Kernel dumped! Time: %d seconds", math.floor(total_time))
        else
            local minutes = math.floor(total_time / 60)
            local seconds = math.floor(total_time - (minutes * 60))
            completion_msg = string.format("Kernel dumped! Time: %d:%02d", minutes, seconds)
        end
        
        send_ps_notification(completion_msg)
    end
    
    -- Always close file descriptor if it was opened
    if fd and fd >= 0 then
        syscall.close(fd)
    end
    
    return dump_success
end

function main()
    if PLATFORM ~= "ps4" then
        error("this payload only targets ps4")
    end
    
    check_jailbroken()
    
    dump_kernel_elf()
end

main()