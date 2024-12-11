-- Parts taken from Al-Azif's FTP Server, so credits to Al-Azif!

-- FileZilla Setup:
-- Open the Site Manager.
-- In General tab, set encryption to "Only use plain FTP (insecure)". We don't have TLS, yet.
-- In Transfer Settings tab, set to "Active"
-- And don't forget to change the IP in this file on line 27 to match your PS4 / PS5's ip.

-- known issues:
-- entering a directory MAY (not always) shutdown the connection to user.
-- transferring files can shutdown the connection to user.

-- todo:
-- fix whatever it is that's slowing down the server.
-- send files and receive files
-- auth tls
-- support more ftp commands.

-- @horror.
conn_types = {
    none = 0x0,
    active = 0x1,
    passive = 0x2
}

ftp = {
    server = {
        ip = "127.0.0.1", -- change this to match your ps4 / ps5's ip. use comma, and not dots.
        port = 1337,      -- ftp port.

        -- -- -- --
        server_sockfd = nil,
        server_sockaddr = bump.alloc(16),
        
        default_file_buf = 0x200
    },
    client = {
        ctrl_sockfd = nil,
        data_sockfd = nil,
        pasv_sockfd = nil,

        data_sockaddr = bump.alloc(16),
        pasv_sockaddr = bump.alloc(16),
        ctrl_sockaddr = bump.alloc(16),

        pasv_sockaddr_len = bump.alloc(8),
        ctrl_sockaddr_len = bump.alloc(8),

        pasv_port = 9045,
        data_port = nil,

        root_path = "/",
        cur_path = "",
        conn_type = conn_types.none,
        transfer_type = "A",
        restore_point = 0
    }
}

-- freebsd sdk and ps4-payload-sdk
SCE_NET_SO_REUSEADDR = 0x00000004 -- allow local address reuse
SCE_NET_SOL_SOCKET = 0xFFFF

-- freebsd sdk ![start]
function S_ISDIR(m) return bit32.band(m, tonumber("0170000", 8)) == tonumber("0040000", 8) end  -- directory

function S_ISCHR(m) return bit32.band(m, tonumber("0170000", 8)) == tonumber("0020000", 8) end  -- char special

function S_ISBLK(m) return bit32.band(m, tonumber("0170000", 8)) == tonumber("0060000", 8) end  -- block special

function S_ISREG(m) return bit32.band(m, tonumber("0170000", 8)) == tonumber("0100000", 8) end  -- regular file

function S_ISFIFO(m) return bit32.band(m, tonumber("0170000", 8)) == tonumber("0010000", 8) end -- fifo or socket

function S_ISLNK(m) return bit32.band(m, tonumber("0170000", 8)) == tonumber("0120000", 8) end  -- symbolic link

function S_ISSOCK(m) return bit32.band(m, tonumber("0170000", 8)) == tonumber("0140000", 8) end -- socket

function S_ISWHT(m) return bit32.band(m, tonumber("0170000", 8)) == tonumber("0160000", 8) end  -- whiteout

-- offsets
function TIMESPEC_TV_SEC() return 0 end

function TIMESPEC_TV_NANO() return 0x8 end

-- freebsd sdk ![end]

function sceKernelSendNotificationRequest(text)
    local O_WRONLY = 1
    local notify_buffer_size = 0xc30
    local notify_buffer = bump.alloc(notify_buffer_size)
    local icon_uri = "cxml://psnotification/tex_icon_system"

    -- credits to OSM-Made for this one. @ https://github.com/OSM-Made/PS4-Notify
    memory.write_dword(notify_buffer + 0, 0)                -- type
    memory.write_dword(notify_buffer + 0x28, 0)             -- unk3
    memory.write_dword(notify_buffer + 0x2C, 1)             -- use_icon_image_uri
    memory.write_dword(notify_buffer + 0x10, -1)            -- target_id
    memory.write_buffer(notify_buffer + 0x2D, text .. "\0") -- message
    memory.write_buffer(notify_buffer + 0x42D, icon_uri)    -- uri

    local notification_fd = syscall.open("/dev/notification0", O_WRONLY):tonumber()
    if notification_fd < 0 then
        error("open() error: " .. get_error_string())
    end

    syscall.write(notification_fd, notify_buffer, notify_buffer_size)

    syscall.close(notification_fd)
end

-- custom reads. for any that has the sizeof 4 bytes, use memory.read_dword instead.
-- we don't really need any additional functions for write, as we can just use memory.write_buffer(addy, val, len) :)
function read_u8(addr)
    local f = memory.read_buffer(addr, 1)
    return f:byte(1)
end

function read_u16(addr)
    local f = memory.read_buffer(addr, 2)
    local lo = f:byte(2)
    local hi = f:byte(1)
    return bit32.bor(hi, bit32.lshift(lo, 8))
end

-- sce wrapper functions ![begin]
function sceNetRecv(sockfd, buf, len, flags)
    return syscall.recvfrom(sockfd, buf, len, flags, 0, 0):tonumber()
end

function sceNetSend(sockfd, buf, len, flags)
    return syscall.sendto(sockfd, buf, len, flags, 0, 0):tonumber()
end

function sceNetListen(sockfd, backlog)
    return syscall.listen(sockfd, backlog):tonumber()
end

function sceNetBind(sockfd, addr, addrlen)
    return syscall.bind(sockfd, addr, addrlen):tonumber()
end

function sceNetSocket(domain, type, protocol)
    return syscall.socket(domain, type, protocol):tonumber()
end

function sceNetSocketClose(sockfd)
    return syscall.close(sockfd):tonumber()
end

function sceNetSetsockopt(sockfd, level, optname, optval, optlen)
    return syscall.setsockopt(sockfd, level, optname, optval, optlen):tonumber()
end

function sceNetHtonl(hostlong)
    return bit32.bor(
        bit32.lshift(bit32.band(hostlong, 0xFF), 24),
        bit32.lshift(bit32.band(hostlong, 0xFF00), 8),
        bit32.rshift(bit32.band(hostlong, 0xFF0000), 8),
        bit32.rshift(bit32.band(hostlong, 0xFF000000), 24)
    )
end

function sceNetHtons(hostshort)
    return bit32.bor(
        bit32.lshift(bit32.band(hostshort, 0xFF), 8),
        bit32.rshift(bit32.band(hostshort, 0xFF00), 8)
    )
end

function sceNetAccept(sockfd, addr, addrlen)
    return syscall.accept(sockfd, addr, addrlen):tonumber()
end

function sceNetConnect(sockfd, addr, addrlen)
    return syscall.connect(sockfd, addr, addrlen):tonumber()
end

function sceNetGetsockname(sockfd, addr, addrlen)
    return syscall.getsockname(sockfd, addr, addrlen):tonumber()
end

function sceStat(path, st)
    return syscall.stat(path, st):tonumber()
end

function sceOpen(path, flags, mode)
    return syscall.open(path, flags, mode):tonumber()
end

function sceRead(fd, buf, len)
    return syscall.read(fd, buf, len):tonumber()
end

function sceLseek(fd, offset, whence)
    return syscall.lseek(fd, offset, whence):tonumber()
end

function sceGetdents(sck, buf, len)
    return syscall.getdents(sck, buf, len):tonumber()
end

function sceClose(sck)
    return syscall.close(sck):tonumber()
end

function sceNetInetPton(addr)
    local a, b, c, d = addr:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    local ip_binary = (a * 256 ^ 3) + (b * 256 ^ 2) + (c * 256) + d
    local f0 = bit32.band(bit32.rshift(ip_binary, 24), 0xFF)
    local f1 = bit32.band(bit32.rshift(ip_binary, 8), 0xFF00)
    local f2 = bit32.band(bit32.lshift(ip_binary, 8), 0xFF0000)
    local f3 = bit32.band(bit32.lshift(ip_binary, 24), 0xFF000000)
    return bit32.bor(f0, f1, f2, f3)
end

-- sce wrapper functions ![end]

-- helper funcs ![begin]
function gen_ftp_fullpath(p)
    return string.format("%s/%s", ftp.client.cur_path, p)
end
-- helper funcs ![end]

function ftp_open_data_conn()
    if ftp.client.conn_type == conn_types.active then
        sceNetConnect(ftp.client.data_sockfd, ftp.client.data_sockaddr, 16)
    else
        memory.write_word(ftp.client.pasv_sockaddr_len, 16)
        ftp.client.pasv_sockfd = sceNetAccept(ftp.client.data_sockfd, ftp.client.pasv_sockaddr,
            ftp.client.pasv_sockaddr_len)
    end
end

function ftp_close_data_conn()
    sceNetSocketClose(ftp.client.data_sockfd)
    if ftp.client.conn_type == conn_types.passive then
        sceNetSocketClose(ftp.client.pasv_sockfd)
    end
    ftp.client.conn_type = conn_types.none
end

function ftp_send_data_msg(str)
    if ftp.client.conn_type == conn_types.active then
        sceNetSend(ftp.client.data_sockfd, str, #str, 0)
    else
        sceNetSend(ftp.client.pasv_sockfd, str, #str, 0)
    end
end

function ftp_send_ctrl_msg(str)
    return sceNetSend(ftp.client.ctrl_sockfd, str, #str, 0)
end

function ftp_send_welcome()
    ftp_send_ctrl_msg("220 RLL FTP Server\r\n")
end

function ftp_file_type_char(mode)
    if S_ISBLK(mode) then
        return 'b'
    elseif S_ISCHR(mode) then
        return 'c'
    elseif S_ISREG(mode) then
        return '-'
    elseif S_ISDIR(mode) then
        return 'd'
    elseif S_ISFIFO(mode) then
        return 'p'
    elseif S_ISSOCK(mode) then
        return 's'
    elseif S_ISLNK(mode) then
        return 'l'
    elseif S_ISWHT(mode) then
        return 'w'
    else
        return ' '
    end
end

function dir_up(path)
    if path == "/" then
        return "/"
    end
    local last_slash = path:match("^(.*)/")
    return last_slash or "/"
end

function file_type_char(mode)
    if S_ISBLK(mode) then
        return "b"
    elseif S_ISCHR(mode) then
        return "c"
    elseif S_ISREG(mode) then
        return "-"
    elseif S_ISDIR(mode) then
        return "d"
    elseif S_ISFIFO(mode) then
        return "p"
    elseif S_ISSOCK(mode) then
        return "s"
    elseif S_ISLNK(mode) then
        return "l"
    else
        return " "
    end
end

function list_args(mode)
    local f = ""
    f = f .. file_type_char(mode)
    f = f .. (bit32.band(mode, tonumber("0400", 8)) > 0 and "r" or "-")
    f = f .. (bit32.band(mode, tonumber("0200", 8)) > 0 and "w" or "-")
    f = f .. (bit32.band(mode, tonumber("0100", 8)) > 0 and (S_ISDIR(mode) and "s" or "x") or (S_ISDIR(mode) and "S" or "-"))
    f = f .. (bit32.band(mode, tonumber("0040", 8)) > 0 and "r" or "-")
    f = f .. (bit32.band(mode, tonumber("0020", 8)) > 0 and "w" or "-")
    f = f .. (bit32.band(mode, tonumber("0010", 8)) > 0 and (S_ISDIR(mode) and "s" or "x") or (S_ISDIR(mode) and "S" or "-"))
    f = f .. (bit32.band(mode, tonumber("0004", 8)) > 0 and "r" or "-")
    f = f .. (bit32.band(mode, tonumber("0002", 8)) > 0 and "w" or "-")
    f = f .. (bit32.band(mode, tonumber("0001", 8)) > 0 and (S_ISDIR(mode) and "s" or "x") or (S_ISDIR(mode) and "S" or "-"))
    return f
end


function ftp_send_list()
    local st = bump.alloc(120)

    if sceStat(ftp.client.cur_path, st) < 0 then
        ftp_send_ctrl_msg(string.format("550 Invalid directory. Got %s\r\n", ftp.client.cur_path))
        return
    end

    local fd = sceOpen(ftp.client.cur_path, 0, 0)
    if fd < 0 then
        ftp_send_ctrl_msg(string.format("550 Invalid directory. Got %s\r\n", ftp.client.cur_path))
        return
    end

    local contents = bump.alloc(512)
    if sceGetdents(fd, contents, 512) < 0 then
        sceClose(fd)
        ftp_send_ctrl_msg(string.format("550 Invalid directory. Got %s\r\n", ftp.client.cur_path))
        return
    end

    ftp_send_ctrl_msg(string.format("150 Opening ASCII mode data transfer for LIST :: %s\r\n", ftp.client.cur_path))
    ftp_open_data_conn()

    local entry = contents
    while true do
        local len = read_u8(entry + 0x4)
        if len == 0 then
            break
        end
        local name = memory.read_buffer(entry + 0x8, 64)
        if name == '\0' then break end
        if #name <= 2 then break end
        local file_st = bump.alloc(120)
        if sceStat(ftp.client.cur_path .. "/" .. name, file_st) < 0 then
            break
        end
        local file_mode = read_u16(file_st + 8)
        local file_size = memory.read_qword(file_st + 72):tonumber()

        if not S_ISLNK(file_mode) then
            ftp_send_data_msg(string.format("%s 1 ps4 ps4 %d Dec 10 12:34 %s\r\n", list_args(file_mode), file_size, name))
        end
        entry = entry + len
    end

    ftp_close_data_conn()
    ftp_send_ctrl_msg("226 Transfer complete.\r\n")

    sceClose(fd)
end

function ftp_send_type(cmd)
    local requested_type = cmd:match("^TYPE (.+)")
    if requested_type == "I" then
        ftp.client.transfer_type = "I"
        ftp_send_ctrl_msg("200 Switching to Binary mode\r\n")
    elseif requested_type == "A" then
        ftp.client.transfer_type = "A"
        ftp_send_ctrl_msg("200 Switching to ASCII mode\r\n")
    else
        ftp_send_ctrl_msg("504 Command not implemented for that parameter\r\n")
    end
end

function ftp_send_pasv()
    local a, b, c, d = ftp.server.ip:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    ftp.client.data_sockfd = sceNetSocket(AF_INET, SOCK_STREAM, 0)

    memory.write_byte(ftp.client.data_sockaddr + 1, AF_INET)
    memory.write_word(ftp.client.data_sockaddr + 2, sceNetHtons(ftp.client.pasv_port))
    memory.write_dword(ftp.client.data_sockaddr + 4, sceNetHtonl(INADDR_ANY))

    sceNetBind(ftp.client.data_sockfd, ftp.client.data_sockaddr, 16)

    sceNetListen(ftp.client.data_sockfd, 128)

    local pasv_port_high = math.floor(ftp.client.pasv_port / 256);
    local pasv_port_low = ftp.client.pasv_port % 256;
    local cmd = string.format("227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)\r\n", a, b, c, d, pasv_port_high, pasv_port_low)
    ftp_send_ctrl_msg(cmd)
    ftp.client.conn_type = conn_types.passive
end

function ftp_send_cwd(cmd)
    local new_path = cmd:match("^CWD (.+)")

    if not new_path then
        ftp_send_ctrl_msg("500 Syntax error, command unrecognized.\r\n")
        return
    end

    if new_path == "/" then
        ftp.client.cur_path = "/"
    elseif new_path == ".." then
        ftp.client.cur_path = dir_up(ftp.client.cur_path)
    else
        local tmp_path
        if new_path:sub(1, 1) == "/" then
            tmp_path = new_path
        else
            if ftp.client.cur_path == "/" then
                tmp_path = ftp.client.cur_path .. new_path
            else
                tmp_path = ftp.client.cur_path .. "/" .. new_path
            end
        end

        if tmp_path ~= "/" then
            if sceOpen(tmp_path, 0, 0) < 0 then
                ftp_send_ctrl_msg("550 Invalid directory.\r\n")
                return
            end
        end

        ftp.client.cur_path = tmp_path
        ftp_send_ctrl_msg("250 Requested file action okay, completed.\r\n")
    end
end

function ftp_send_port(cmd)
    local ip1, ip2, ip3, ip4, port_hi, port_lo = cmd:match("^PORT (%d+),(%d+),(%d+),(%d+),(%d+),(%d+)")
    if not ip1 or not port_hi then
        return
    end

    local data_port = tonumber(port_lo) + tonumber(port_hi) * 256
    if not data_port then
        return
    end

    ftp.client.data_sockfd = sceNetSocket(AF_INET, SOCK_STREAM, 0)
    if ftp.client.data_sockfd < 0 then
        return
    end

    local ip_bin_str = string.format("%d.%d.%d.%d", ip1, ip2, ip3, ip4)
    local ip_bin = sceNetInetPton(ip_bin_str)
    
    memory.write_byte(ftp.client.data_sockaddr + 1, AF_INET)
    memory.write_word(ftp.client.data_sockaddr + 2, sceNetHtons(data_port))
    memory.write_dword(ftp.client.data_sockaddr + 4, ip_bin) -- Hardcoded IP (for now.)

    ftp.client.conn_type = conn_types.active
    ftp_send_ctrl_msg("200 PORT command ok\r\n")
end

function ftp_send_syst()
    ftp_send_ctrl_msg("215 UNIX Type: L8\r\n");
end

function ftp_send_feat()
    ftp_send_ctrl_msg("211-extensions\r\n");
    ftp_send_ctrl_msg("REST STREAM\r\n");
    ftp_send_ctrl_msg("211 end\r\n");
end

function ftp_send_cdup()
    ftp.client.cur_path = dir_up(ftp.client.cur_path);
    ftp_send_ctrl_msg("200 Command okay\r\n")
end

function ftp_send_data_raw(buf, len)
    if ftp.client.conn_type == conn_types.active then
        sceNetSend(ftp.client.data_sockfd, buf, len, 0)
    else
        sceNetSend(ftp.client.pasv_sockfd, buf, len, 0)
    end
end

function ftp_send_file(path)
    local fd = sceOpen(path, 0, 0)
    if fd >= 0 then
        sceLseek(fd, ftp.client.restore_point, 0)

        local buffer = bump.alloc(ftp.server.default_file_buf+1)
        ftp_open_data_conn()
        ftp_send_ctrl_msg("150 Opening Image mode data transfer\r\n")

        while true do
            local n_recv = sceRead(fd, buffer, ftp.server.default_file_buf)
            if n_recv > 0 then
                ftp_send_data_raw(buffer, n_recv)
            else
                break
            end
        end

        sceClose(fd)
        ftp_send_ctrl_msg("226 Transfer completed\r\n")
        ftp_close_data_conn()
    else
        ftp_send_ctrl_msg("550 File not found\r\n")
    end
end

function ftp_client_th()
    local recv_buffer = bump.alloc(512)
    local recv_len = nil
    ftp_send_welcome() -- send welcome msg to filezilla

    while true do
        recv_len = sceNetRecv(ftp.client.ctrl_sockfd, recv_buffer, 512, 0)
        if recv_len <= 0 then break end

        local cmd = memory.read_buffer(recv_buffer, recv_len):gsub("\r\n", "") -- ftp commands.

        if cmd:match("^USER") then
            ftp_send_ctrl_msg("331 Anonymous login accepted, send your email as password\r\n")
        elseif cmd:match("^NOOP") then
            ftp_send_ctrl_msg("200 No operation\r\n")
        elseif cmd:match("^PASS") then
            ftp_send_ctrl_msg("230 User logged in\r\n")
        elseif cmd:match("^PWD") then
            ftp_send_ctrl_msg(string.format("257 \"%s\" is the current directory\r\n", ftp.client.cur_path))
        elseif cmd:match("^TYPE (.+)") then
            ftp_send_type(cmd)
        elseif cmd:match("^PASV") then
            ftp_send_pasv()
        elseif cmd:match("^LIST") then
            ftp_send_list()
        elseif cmd:match("^CWD") then
            ftp_send_cwd(cmd)
        elseif cmd:match("^CDUP") then
            ftp_send_cdup()
        elseif cmd:match("^PORT") then
            ftp_send_port(cmd)
        elseif cmd:match("^SYST") then
            ftp_send_syst()
        elseif cmd:match("^FEAT") then
            ftp_send_feat()
        elseif cmd:match("^RETR") then
            ftp_send_file("/app0/sce_module/libc.prx")
        elseif cmd:match("^STOR") then
            ftp_send_file("/app0/sce_module/libc.prx")

        elseif cmd:match("^QUIT") then
            ftp_send_ctrl_msg("221 Goodbye\r\n")
            break
        else
            sceKernelSendNotificationRequest("Requested: " .. cmd .. ", But it's not implemented.")
        end
    end
    sceNetSocketClose(ftp.client.ctrl_sockfd)
end

function ftp_init()
    ftp.client.cur_path = ftp.client.root_path
    ftp.server.server_sockfd = sceNetSocket(AF_INET, SOCK_STREAM, 0)
    if ftp.server.server_sockfd < 0 then
        errorf("sceNetSocket() error: " .. get_error_string())
        return
    end

    local enable = bump.alloc(4)
    memory.write_dword(enable, 1)
    if sceNetSetsockopt(ftp.server.server_sockfd, SCE_NET_SOL_SOCKET, SCE_NET_SO_REUSEADDR, enable, 4) < 0 then
        errorf("sceNetSetsockopt() error: " .. get_error_string())
        sceNetSocketClose(ftp.server.server_sockfd)
        return
    end

    memory.write_byte(ftp.server.server_sockaddr + 1, AF_INET)
    memory.write_word(ftp.server.server_sockaddr + 2, sceNetHtons(ftp.server.port))
    memory.write_dword(ftp.server.server_sockaddr + 4, sceNetHtonl(INADDR_ANY))

    if sceNetBind(ftp.server.server_sockfd, ftp.server.server_sockaddr, 16) < 0 then
        errorf("sceNetBind() error(INIT): " .. get_error_string())
        sceNetSocketClose(ftp.server.server_sockfd)
        return
    end

    if sceNetListen(ftp.server.server_sockfd, 128) < 0 then
        errorf("sceNetListen() error: " .. get_error_string())
        sceNetSocketClose(ftp.server.server_sockfd)
        return
    end

    sceKernelSendNotificationRequest("FTP Server listening on port " .. ftp.server.port)

    while true do
        ftp.client.ctrl_sockfd = sceNetAccept(ftp.server.server_sockfd, ftp.client.ctrl_sockaddr,
            ftp.client.ctrl_sockaddr_len)
        if ftp.client.ctrl_sockfd >= 0 then
            local client_th = coroutine.create(ftp_client_th)
            coroutine.resume(client_th, "client_thread")
            coroutine.yield()
            --sceNetSocketClose(ftp.client.ctrl_sockfd)
            break
        end
    end
    sceNetSocketClose(ftp.server.server_sockfd)
    sceKernelSendNotificationRequest("FTP Server closed")
end

function main()
    syscall.resolve({
        unlink = 10,
        recvfrom = 29, -- recv.
        getsockname = 32,
        access = 33,
        readlink = 58,
        connect = 98,
        sendto = 133, -- send.
        mkdir = 136,
        rmdir = 137,
        stat = 188,
        getdirentries = 196,
        getdents = 272,
        sendfile = 393,
        lseek = 478
    })

    local ftp_co = coroutine.create(ftp_init)
    coroutine.resume(ftp_co, "ftp_task")
end

main()
