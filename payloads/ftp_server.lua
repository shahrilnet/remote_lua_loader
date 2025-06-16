-- Parts taken from Al-Azif's FTP Server, so credits to Al-Azif!

-- FileZilla Setup:
-- Open the Site Manager.
-- In General tab, set encryption to "Only use plain FTP (insecure)". We don't have TLS, yet.

-- known issues:
-- transferring a large file may crash the application.

-- @horror.
FTP_DEBUG_MSG = "on"
conn_types = {
    none = 0x0,
    active = 0x1,
    passive = 0x2
}

ftp = {
    server = {
        ip = "127.0.0.1",
        port = 1337,      -- ftp port.

        -- -- -- --
        server_sockfd = nil,
        server_sockaddr = memory.alloc(16),
        
        default_file_buf = 0x200,
        rname = ""
    },
    client = {
        ctrl_sockfd = nil,
        data_sockfd = nil,
        pasv_sockfd = nil,

        data_sockaddr = memory.alloc(16),
        pasv_sockaddr = memory.alloc(16),
        ctrl_sockaddr = memory.alloc(16),

        pasv_sockaddr_len = memory.alloc(8),
        ctrl_sockaddr_len = memory.alloc(8),

        data_port = nil,

        root_path = "/",
        cur_path = "",
        conn_type = conn_types.none,
        transfer_type = "I",
        restore_point = -1,
        is_connected = false,
        cur_cmd = nil
    }
}

offsets = {
    libc = {
        raspberry_cube = {
            time = 0xB6130,
            gmtime = 0x3E320,
            gmtime_s = 0x350B0
        },
        aibeya = {
            time = 0xB4F00,
            gmtime = 0x3DA60,
            gmtime_s = 0x34790
        },
        aikagi_2 = {
            time = 0xB2EF0,
            gmtime = 0x33800,
            gmtime_s = 0x2A480
        },
        hamidashi_creative = {
            time = 0xAF920,
            gmtime = 0x31BB0,
            gmtime_s = 0x287D0
        },
        aikagi_kimi_isshoni_pack = {
            time = 0xB6130,
            gmtime = 0x3E320,
            gmtime_s = 0x350B0
        },
        c = {
            time = 0x70EB0,
            gmtime = 0x469E0,
            gmtime_s = 0x3F540
        },
        e = {
            time = 0x7EEA0,
            gmtime = 0x96D0,
            gmtime_s = 0x1640
        },
        ixshe_tell = {
            time = 0xB4F00,
            gmtime = 0x3DA60,
            gmtime_s = 0x34790
        },
        nora_princess = {
            time = 0x7FBB0,
            gmtime = 0x9730,
            gmtime_s = 0x1600
        },
        jinki_resurrection = {
            time = 0xB0AB0,
            gmtime = 0x32150,
            gmtime_s = 0x28D80
        },
        fuyu_kiss = {
            time = 0xAFD30,
            gmtime = 0x31B00,
            gmtime_s = 0x287A0
        },
        nora_princess2 = {
            time = 0x7FBB0,
            gmtime = 0x9730,
            gmtime_s = 0x1600
        },
        f = {
            time = 0xB2660,
            gmtime = 0x33800,
            gmtime_s = 0x2A480
        },
    }
}

local add_offsets = {}
function get_offsets(gamename)
    if gamename == "RaspberryCube" then add_offsets = offsets.libc.raspberry_cube end
    if gamename == "Aibeya" then add_offsets = offsets.libc.aibeya end
    if gamename == "Aikagi2" then add_offsets = offsets.libc.aikagi_2 end
    if gamename == "HamidashiCreative" then add_offsets = offsets.libc.hamidashi_creative end
    if gamename == "AikagiKimiIsshoniPack" then add_offsets = offsets.libc.aikagi_kimi_isshoni_pack end
    if gamename == "C" then add_offsets = offsets.libc.c end
    if gamename == "E" then add_offsets = offsets.libc.e end
    if gamename == "IxSHETell" then add_offsets = offsets.libc.ixshe_tell end
    if gamename == "NoraPrincess" then add_offsets = offsets.libc.nora_princess end
    if gamename == "JinkiResurrection" then add_offsets = offsets.libc.jinki_resurrection end
    if gamename == "FuyuKiss" then add_offsets = offsets.libc.fuyu_kiss end
    if gamename == "NoraPrincess2" then add_offsets = offsets.libc.nora_princess2 end
    if gamename == "F" then add_offsets = offsets.libc.f end

    -- check if offsets table is empty
    if next(add_offsets) == nil then
        error("libc game offsets for FTP server not found! Exiting")
    end
end

function time(tloc)
    local tmp = fcall(libc_base+add_offsets.time)
    return tmp(tloc):tonumber() --i64
end

function gmtime(timep)
    local tmp = fcall(libc_base+add_offsets.gmtime)
    return tmp(timep):tonumber() --tm* (36 bytes size ptr)
end

function gmtime_s(timep, result)
    local tmp = fcall(libc_base+add_offsets.gmtime_s)
    return tmp(timep, result):tonumber() --tm* (36 bytes size ptr)
end

-- freebsd sdk and ps4-payload-sdk
AF_INET = 2
SOCK_STREAM = 1
INADDR_ANY = 0
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

function sceKernelSendDebug(text)
    if FTP_DEBUG_MSG == "on" then
        send_ps_notification(text)
    end
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

function sceWrite(fd, buf, len)
    return syscall.write(fd, buf, len):tonumber()
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

function sceMkdir(path, mode)
    return syscall.mkdir(path, mode):tonumber()
end

function sceRmdir(path)
    return syscall.rmdir(path):tonumber()
end

function sceRename(old, new)
    return syscall.rename(old, new):tonumber()
end

function sceUnlink(path)
    return syscall.unlink(path):tonumber()
end

function sceChmod(path, mode)
    return syscall.chmod(path, mode):tonumber()
end

function sceFileExists(path)
    local st = memory.alloc(120)
    if sceStat(path, st) < 0 then 
        return false
    else
        return true
    end
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

function ftp_open_data_conn()
    if ftp.client.conn_type == conn_types.active then
        sceNetConnect(ftp.client.data_sockfd, ftp.client.data_sockaddr, 16)
    else
        memory.write_byte(ftp.client.pasv_sockaddr_len, 16)
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
    sceNetSend(ftp.client.ctrl_sockfd, str, #str, 0)
end

function ftp_send_welcome()
    ftp_send_ctrl_msg("220 RLL FTP Server\r\n")
end

function sanitize_path(from, to)
    if to:match(".*/") then
        to = to:match(".*/(.*)")
    end
    return string.format("%s/%s", from, to)
end

function dir_up(path)
    if path == "/" then
        return "/"
    end
    local last_slash = path:match("^(.*)/")
    return last_slash or "/"
end

function file_type_char(mode)
    local type_map = {
        [S_ISBLK] = 'b',   -- Block device
        [S_ISCHR] = 'c',   -- Character device
        [S_ISREG] = '-',   -- Regular file
        [S_ISDIR] = 'd',   -- Directory
        [S_ISFIFO] = 'p',  -- FIFO/pipe
        [S_ISSOCK] = 's',  -- Socket
        [S_ISLNK] = 'l',   -- Symbolic link
        [S_ISWHT] = 'w'    -- Whiteout
    }

    for check_func, character in pairs(type_map) do
        if check_func(mode) then
            return character
        end
    end

    return ' '
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

function ftp_send_size()
    local st = memory.alloc(120)
    local dir = ftp.client.cur_path
    if sceStat(dir, st) < 0 then
        ftp_send_ctrl_msg("550 The file doesn't exist\r\n")
        return
    end
    local file_size = memory.read_qword(st + 72):tonumber()
    ftp_send_ctrl_msg(string.format("213 %d\r\n", file_size))
end

function ftp_send_list()
    local st = memory.alloc(120)

    if sceStat(ftp.client.cur_path, st) < 0 then
        ftp_send_ctrl_msg(string.format("550 Invalid directory. Got %s\r\n", ftp.client.cur_path))
        return
    end

    local fd = sceOpen(ftp.client.cur_path, 0, 0)
    if fd < 0 then
        ftp_send_ctrl_msg(string.format("550 Invalid directory. Got %s\r\n", ftp.client.cur_path))
        return
    end

    local contents = memory.alloc(4096)  -- bigger buffer, good
    local months = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" }

    ftp_send_ctrl_msg("150 Opening ASCII mode data transfer for LIST.\r\n")
    ftp_open_data_conn()

    while true do
        local nread = sceGetdents(fd, contents, 4096)
        if nread <= 0 then break end

        local entry = contents
        local end_ptr = contents + nread

        while entry < end_ptr do
            local length = read_u8(entry + 0x4)
            if length == 0 then break end

            local name = memory.read_buffer(entry + 0x8, 64)

            if name ~= '.' and name ~= '..' and name ~= '\0' then
                local full_path = ftp.client.cur_path .. "/" .. name
                if sceStat(full_path, st) >= 0 then
                    local file_mode = read_u16(st + 8)
                    local file_size = memory.read_qword(st + 72):tonumber()

                    local tm = memory.alloc(36)
                    gmtime_s(st + 56, tm)
                    local n_hour = memory.read_dword(tm + 8)
                    local n_mins = memory.read_dword(tm + 4)
                    local n_mday = memory.read_dword(tm + 12)
                    local n_mon = memory.read_dword(tm + 16)

                    ftp_send_data_msg(string.format("%s 1 ps4 ps4 %d %s %d %02d:%02d %s\r\n",
                        list_args(file_mode),
                        file_size,
                        months[n_mon:tonumber()+1],
                        n_mday:tonumber(),
                        n_hour:tonumber(),
                        n_mins:tonumber(),
                        name))
                end
            end

            entry = entry + length
        end
    end

    sceClose(fd)
    ftp_close_data_conn()
    ftp_send_ctrl_msg("226 Transfer complete\r\n")
end

function ftp_send_type()
    local requested_type = ftp.client.cur_cmd:match("^TYPE (.+)")
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

    local ip_bin_str = string.format("%d.%d.%d.%d", a, b, c, d)
    local ip_bin = sceNetInetPton(ip_bin_str)

    memory.write_byte(ftp.client.data_sockaddr + 1, AF_INET)
    memory.write_word(ftp.client.data_sockaddr + 2, sceNetHtons(0))
    memory.write_dword(ftp.client.data_sockaddr + 4, ip_bin)

    sceNetBind(ftp.client.data_sockfd, ftp.client.data_sockaddr, 16)

    sceNetListen(ftp.client.data_sockfd, 128)

    local picked = memory.alloc(16)
    local namelen = memory.alloc(8)
    memory.write_byte(namelen, 16)
    sceNetGetsockname(ftp.client.data_sockfd, picked, namelen)

    local port = read_u16(picked + 2)
    --send_ps_notification("Port: " .. port)

    local cmd = string.format("227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)\r\n", a, b, c, d, bit32.bor(bit32.rshift(port, 0), 0xFF), bit32.bor(bit32.rshift(port, 8), 0xFF))
    ftp_send_ctrl_msg(cmd)
    ftp.client.conn_type = conn_types.passive
end

function ftp_send_cwd()
    local new_path = ftp.client.cur_cmd:match("^CWD (.+)")
    sceKernelSendDebug(ftp.client.cur_cmd)

    if not new_path then
        ftp_send_ctrl_msg("500 Syntax error, command unrecognized.\r\n")
        return
    end

    if new_path == "/" then
        ftp.client.cur_path = "/"
        ftp_send_ctrl_msg("250 Requested file action okay, completed.\r\n")
    elseif new_path == ".." then
        ftp.client.cur_path = dir_up(ftp.client.cur_path)
        if ftp.client.cur_path ~= "/" then
            ftp.client.cur_path = "/"
        end
        ftp_send_ctrl_msg("250 Requested file action okay, completed.\r\n")
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

function ftp_send_port()
    local ip1, ip2, ip3, ip4, port_hi, port_lo = ftp.client.cur_cmd:match("^PORT (%d+),(%d+),(%d+),(%d+),(%d+),(%d+)")
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

    local ip_bin = sceNetInetPton(string.format("%d.%d.%d.%d", ip1, ip2, ip3, ip4))
    
    memory.write_byte(ftp.client.data_sockaddr + 1, AF_INET)
    memory.write_word(ftp.client.data_sockaddr + 2, sceNetHtons(data_port))
    memory.write_dword(ftp.client.data_sockaddr + 4, ip_bin)

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
    if not ftp.client.cur_path or ftp.client.cur_path == "" then ftp.client.cur_path = "/" end
    if ftp.client.cur_path ~= "/" then
        ftp.client.cur_path = dir_up(ftp.client.cur_path)
    end
    ftp_send_ctrl_msg("200 Command okay\r\n")
end

function ftp_send_data_raw(buf, len)
    if ftp.client.conn_type == conn_types.active then
        sceNetSend(ftp.client.data_sockfd, buf, len, 0)
    else
        sceNetSend(ftp.client.pasv_sockfd, buf, len, 0)
    end
end

function ftp_recv_data_raw(buf, len)
    if ftp.client.conn_type == conn_types.active then
        return sceNetRecv(ftp.client.data_sockfd, buf, len, 0)
    else
        return sceNetRecv(ftp.client.pasv_sockfd, buf, len, 0)
    end
end

function ftp_send_file(path)
    local fd = sceOpen(path, 0, 0)
    if fd < 0 then
        ftp_send_ctrl_msg("550 File not found\r\n")
        return
    end
    
    sceLseek(fd, ftp.client.restore_point, 0)
    local st = memory.alloc(120)

    if sceStat(path, st) < 0 then
        ftp_send_ctrl_msg("550 File not found\r\n")
        return
    end

    local file_size = memory.read_qword(st + 72):tonumber()
    local chunk_size = 8192 
    local buffer = memory.alloc(chunk_size)
    local bytes_sent = 0
    ftp_open_data_conn()
    ftp_send_ctrl_msg("150 Opening Image mode data transfer\r\n")

    while bytes_sent < file_size do
        local bytes_to_read = math.min(chunk_size, file_size - bytes_sent)
        local n_recv = sceRead(fd, buffer, bytes_to_read)

        if n_recv <= 0 then break end
        ftp_send_data_raw(buffer, n_recv)
        bytes_sent = bytes_sent + n_recv
    end

    sceClose(fd)
    ftp_send_ctrl_msg("226 Transfer completed\r\n")
    ftp_close_data_conn()
end

function ftp_recv_file(path)
    O_CREATE = 0x0200
    O_RDWR = 0x0002
    O_APPEND = 0x0008
    O_TRUNC = 0x0400

    local mode = bit32.bor(O_CREATE, O_RDWR)

    if ftp.client.restore_point then
        mode = bit32.bor(mode, O_APPEND)
    else
        mode = bit32.bor(mode, O_TRUNC)
    end

    local fd = sceOpen(path, mode, tonumber("0777", 8))
    if fd < 0 then
        ftp_send_ctrl_msg("500 Error opening file\r\n")
        return
    end
    
    ftp_open_data_conn()
    ftp_send_ctrl_msg("150 Opening Image mode data transfer\r\n")

    local chunk_size = 8192
    local buffer = memory.alloc(chunk_size)

    while true do
        local n_recv = ftp_recv_data_raw(buffer, chunk_size)
        if n_recv <= 0 then break end 

        local n_written = sceWrite(fd, buffer, n_recv)
        if n_written < n_recv then
            ftp_send_ctrl_msg("550 File write error\r\n")
            break
        end
    end

    ftp_send_ctrl_msg("226 Transfer completed\r\n")
    ftp_close_data_conn()
    sceClose(fd)
end


function ftp_send_retr()
    local path = ftp.client.cur_cmd:match("^RETR (.+)")
    local dir = sanitize_path(ftp.client.cur_path, path)
    sceKernelSendDebug("Requested (RETR): " .. dir)
    
    ftp_send_file(dir)
end

function ftp_send_stor()
    local path = ftp.client.cur_cmd:match("^STOR (.+)")
    local dir = sanitize_path(ftp.client.cur_path, path)
    sceKernelSendDebug("Requested (STOR): " .. dir)

    ftp_recv_file(dir)
end

function ftp_send_appe()
    local path = ftp.client.cur_cmd:match("^STOR (.+)")
    local dir = sanitize_path(ftp.client.cur_path, path)
    sceKernelSendDebug("Requested (APPE): " .. dir)

    ftp.client.restore_point = -1
    ftp_recv_file(dir)
end

function ftp_send_rest()
    local rest = ftp.client.cur_cmd:match("^REST (%d+)")
    ftp.client.restore_point = rest
    sceKernelSendDebug("Requested (REST): " .. rest)

    ftp_send_ctrl_msg(string.format("350 Resuming at %d\r\n", rest))
end

function ftp_send_mkd()
    local path = ftp.client.cur_cmd:match("^MKD (.+)")
    local dir = sanitize_path(ftp.client.cur_path, path)

    sceKernelSendDebug("Requested (MKD): " .. dir)
    local fd = sceOpen(dir, 0, 0)
    if fd >= 0 then
        ftp_send_ctrl_msg("550 Requested action not taken. Folder already exists.\r\n")
    else
        if sceMkdir(dir, tonumber("0755", 8)) < 0 then
            ftp_send_ctrl_msg("501 Syntax error. Not privileged.\r\n")
        else
            ftp_send_ctrl_msg(string.format("257 \"%s\" created.\r\n", path))
        end
    end

    if fd > 0 then
        sceClose(fd)
    end
end

function ftp_send_rmd()
    local path = ftp.client.cur_cmd:match("^RMD (.+)")
    local dir = sanitize_path(ftp.client.cur_path, path)

    sceKernelSendDebug("Requested (RMD): " .. dir)
    local fd = sceOpen(dir, 0, 0)
    if fd >= 0 then
        sceClose(fd)
        if sceRmdir(dir) < 0 then
            ftp_send_ctrl_msg("550 Directory not found or permission denied\r\n")
        else
            ftp_send_ctrl_msg(string.format("250 \"%s\" has been removed\r\n", path))
        end
    else
        ftp_send_ctrl_msg("500 Directory doesn't exist\r\n")
    end
end

function ftp_send_dele()
    local path = ftp.client.cur_cmd:match("^DELE (.+)")
    local dir = sanitize_path(ftp.client.cur_path, path)

    sceKernelSendDebug("Requested (DELE): " .. dir)
    if sceUnlink(dir) < 0 then
        ftp_send_ctrl_msg("550 Could not delete the file\r\n")
    else
        ftp_send_ctrl_msg("226 File deleted\r\n")
    end
end

function ftp_send_rnfr()
    local path = ftp.client.cur_cmd:match("^RNFR (.+)")
    local dir = sanitize_path(ftp.client.cur_path, path)

    sceKernelSendDebug("Requested (RNFR): " .. dir)
    if sceFileExists(dir) then
        ftp.server.rname = path
        ftp_send_ctrl_msg("350 Remembered filename\r\n")
        return
    end
    ftp_send_ctrl_msg("550 The file doesn't exist\r\n")
end

function ftp_send_rnto()
    local path = ftp.client.cur_cmd:match("^RNTO (.+)")
    local dir_old = sanitize_path(ftp.client.cur_path, ftp.server.rname)
    local dir_new = sanitize_path(ftp.client.cur_path, path)

    sceKernelSendDebug("Requested (RNTO): \n" .. dir_old .. "\n" .. dir_new)
    if sceRename(dir_old, dir_new) < 0 then
        ftp_send_ctrl_msg("550 Error renaming file\r\n")
        return
    else
        ftp_send_ctrl_msg("226 Renamed file\r\n")
    end
end

function ftp_send_site()
    local action, rule, path = ftp.client.cur_cmd:match("^SITE (.+) (%d+) (.+)")
    local dir = sanitize_path(ftp.client.cur_path, path)

    if action == "CHMOD" then
        if syscall.chmod(dir, tonumber(string.format("%04d", rule), 8)):tonumber() < 0 then
            ftp_send_ctrl_msg("550 Permission denied\r\n")
        else
            ftp_send_ctrl_msg("200 OK\r\n")
        end
    else
        ftp_send_ctrl_msg("550 Syntax error, command unrecognized\r\n")
    end
end

local command_handlers = {
    USER = function() 
        ftp_send_ctrl_msg("331 Anonymous login accepted, send your email as password\r\n") 
    end,
    NOOP = function() 
        ftp_send_ctrl_msg("200 No operation\r\n") 
    end,
    PASS = function() 
        ftp_send_ctrl_msg("230 User logged in\r\n") 
    end,
    PWD = function() 
        ftp_send_ctrl_msg(string.format("257 \"%s\" is the current directory\r\n", ftp.client.cur_path)) 
    end,
    TYPE = function() 
        ftp_send_type()
    end,
    PASV = function() 
        ftp_send_pasv() 
    end,
    LIST = function() 
        ftp_send_list() 
    end,
    CWD = function()
        ftp_send_cwd()
    end,
    CDUP = function() 
        ftp_send_cdup() 
    end,
    PORT = function() 
        ftp_send_port()
    end,
    SYST = function()
        ftp_send_syst()
    end,
    FEAT = function()
        ftp_send_feat()
    end,
    MKD = function()
        ftp_send_mkd()
    end,
    RMD = function()
        ftp_send_rmd()
    end,
    SIZE = function()
        ftp_send_size()
    end,
    DELE = function()
        ftp_send_dele()
    end,
    RNFR = function()
        ftp_send_rnfr()
    end,
    RNTO = function()
        ftp_send_rnto()
    end,
    RETR = function()
        ftp_send_retr()
    end,
    STOR = function()
        ftp_send_stor()
    end,
    APPE = function()
        ftp_send_appe()
    end,
    REST = function()
        ftp_send_rest()
    end,
    SITE = function()
        ftp_send_site()
    end,
    QUIT = function() 
        ftp_send_ctrl_msg("221 Goodbye\r\n") 
        return true -- break signal
    end
}

local function default_handler()
    ftp_send_ctrl_msg("500 Syntax error, command unrecognized.\r\n")
    sceKernelSendDebug("Requested: " .. ftp.client.cur_cmd .. ", But it's not implemented.")
end

local function cleanup_ftp()
    if ftp.client.ctrl_sockfd then sceClose(ftp.client.ctrl_sockfd) end
    if ftp.client.data_sockfd then sceClose(ftp.client.data_sockfd) end
    if ftp.client.pasv_sockfd then sceClose(ftp.client.pasv_sockfd) end
    if ftp.server.server_sockfd then sceClose(ftp.server.server_sockfd) end
    send_ps_notification("FTP Server closed")
end

function ftp_client_th()
    
    local recv_buffer = memory.alloc(512)
    local recv_len = nil
    ftp_send_welcome()

    while true do
        recv_len = sceNetRecv(ftp.client.ctrl_sockfd, recv_buffer, 512, 0)
        if recv_len <= 0 then break end
    
        local cmd = memory.read_buffer(recv_buffer, recv_len):gsub("\r\n", "") 
        local command = cmd:match("^(%S+)")
        ftp.client.cur_cmd = cmd
        
        local handler = command_handlers[command] or default_handler
        local should_break = handler()
        if should_break then break end
    end
    cleanup_ftp()
end

function ftp_init()
    get_offsets(game_name)

    ftp.client.cur_path = ftp.client.root_path
    ftp.server.server_sockfd = sceNetSocket(AF_INET, SOCK_STREAM, 0)
    if ftp.server.server_sockfd < 0 then
        errorf("sceNetSocket() error: " .. get_error_string())
        return
    end

    local enable = memory.alloc(4)
    memory.write_dword(enable, 1)
    if sceNetSetsockopt(ftp.server.server_sockfd, SCE_NET_SOL_SOCKET, SCE_NET_SO_REUSEADDR, enable, 4) < 0 then
        errorf("sceNetSetsockopt() error: " .. get_error_string())
        sceClose(ftp.server.server_sockfd)
        return
    end

    memory.write_byte(ftp.server.server_sockaddr + 1, AF_INET)
    memory.write_word(ftp.server.server_sockaddr + 2, sceNetHtons(ftp.server.port))
    memory.write_dword(ftp.server.server_sockaddr + 4, sceNetHtonl(INADDR_ANY))

    if sceNetBind(ftp.server.server_sockfd, ftp.server.server_sockaddr, 16) < 0 then
        errorf("sceNetBind() error: " .. get_error_string())
        sceClose(ftp.server.server_sockfd)
        return
    end

    if sceNetListen(ftp.server.server_sockfd, 128) < 0 then
        errorf("sceNetListen() error: " .. get_error_string())
        sceClose(ftp.server.server_sockfd)
        return
    end

    send_ps_notification("FTP Server listening on port " .. ftp.server.port)

    while true do
        if not ftp.client.is_connected then
            ftp.client.ctrl_sockfd = sceNetAccept(ftp.server.server_sockfd, ftp.client.ctrl_sockaddr, ftp.client.ctrl_sockaddr_len)
            if ftp.client.ctrl_sockfd >= 0 then
                ftp.client.is_connected = true
                break
            end
        end
    end

    ftp_client_th()
end

function main()
    syscall.resolve({
        open = 5,
        unlink = 10,
        chmod = 15,
        recvfrom = 29, -- recv.
        getsockname = 32,
        connect = 98,
        rename = 128,
        sendto = 133, -- send.
        mkdir = 136,
        rmdir = 137,
        stat = 188,
        getdents = 272,
        lseek = 478
    })

    ftp_init()
end

main()
