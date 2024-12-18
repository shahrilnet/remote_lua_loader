function sceKernelSendNotificationRequest(text)
    local O_WRONLY = 1
    local notify_buffer_size = 0xc30
    local notify_buffer = bump.alloc(notify_buffer_size)
    local icon_uri = "cxml://psnotification/tex_icon_system"

    -- credits to OSM-Made for this one. @ https://github.com/OSM-Made/PS4-Notify
    memory.write_dword(notify_buffer + 0, 0)            -- type
    memory.write_dword(notify_buffer + 0x28, 0)         -- unk3
    memory.write_dword(notify_buffer + 0x2C, 1)         -- use_icon_image_uri
    memory.write_dword(notify_buffer + 0x10, -1)        -- target_id
    memory.write_buffer(notify_buffer + 0x2D, text .. "\0") -- message
    memory.write_buffer(notify_buffer + 0x42D, icon_uri) -- uri
    
    local notification_fd = syscall.open("/dev/notification0", O_WRONLY):tonumber()
    if notification_fd < 0 then
        error("open() error: " .. get_error_string())
    end
    
    syscall.write(notification_fd, notify_buffer, notify_buffer_size)
    
    syscall.close(notification_fd)
end

function main()
    sceKernelSendNotificationRequest("Hello world")
end

main()
