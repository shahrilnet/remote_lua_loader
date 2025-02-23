local sbl = {}


sbl.DEBUG = 0

function sbl.SOCK_LOG(sock, format, ...)
    local msg = string.format(format, ...)
    if sock then
        sock:send(msg)
    else
        print(msg)
    end
end


sbl.sbl_msg_header = {
    cmd = 0,
    query_len = 0,
    recv_len = 0,
    message_id = 0,
    to_ret = 0
}

sbl.sbl_mailbox_metadata = {
    message_id = 0,
    unk_08h = 0,
    unk_10h = 0
}


sbl.g_sbl_kernel_data_base = 0
sbl.g_sbl_dmap_base = 0
sbl.g_sbl_kernel_offset_dmpml4i = 0
sbl.g_sbl_kernel_offset_dmpdpi = 0
sbl.g_sbl_kernel_offset_pml4pml4i = 0
sbl.g_sbl_kernel_offset_mailbox_base = 0
sbl.g_sbl_kernel_offset_mailbox_flags = 0
sbl.g_sbl_kernel_offset_mailbox_meta = 0
sbl.g_sbl_kernel_offset_mailbox_mtx = 0
sbl.g_sbl_kernel_offset_g_message_id = 0
sbl.g_sbl_mailbox_marked_inuse = 0


function sbl.DumpHex(sock, data, size)
    if sbl.DEBUG == 0 then return end
    
    local hex_output = "hex:\n"
    local ascii = {}

    for i = 1, size do
        local byte = string.byte(data, i) or 0
        hex_output = hex_output .. string.format("%02X ", byte)

        if byte >= 32 and byte <= 126 then
            ascii[#ascii + 1] = string.char(byte)
        else
            ascii[#ascii + 1] = "."
        end
        
        if i % 8 == 0 then hex_output = hex_output .. " " end
        if i % 16 == 0 or i == size then
            hex_output = hex_output .. "|  " .. table.concat(ascii) .. "\n"
            ascii = {}
        end
    end

    sbl.SOCK_LOG(sock, hex_output)
end


function sbl.init_sbl(kernel_data_base, dmpml4i_offset, dmpdpi_offset, pml4pml4i_offset, mailbox_base_offset, mailbox_flags_offset, mailbox_meta_offset, mailbox_mtx_offset, g_message_id_offset)
    sbl.g_sbl_kernel_data_base = kernel_data_base
    sbl.g_sbl_kernel_offset_dmpml4i = dmpml4i_offset
    sbl.g_sbl_kernel_offset_dmpdpi = dmpdpi_offset
    sbl.g_sbl_kernel_offset_pml4pml4i = pml4pml4i_offset
    sbl.g_sbl_kernel_offset_mailbox_base = mailbox_base_offset
    sbl.g_sbl_kernel_offset_mailbox_flags = mailbox_flags_offset
    sbl.g_sbl_kernel_offset_mailbox_meta = mailbox_meta_offset
    sbl.g_sbl_kernel_offset_mailbox_mtx = mailbox_mtx_offset
    sbl.g_sbl_kernel_offset_g_message_id = g_message_id_offset

    local DMPML4I, DMPDPI = 0, 0
    kernel_copyout(sbl.g_sbl_kernel_data_base + sbl.g_sbl_kernel_offset_dmpml4i, DMPML4I, 8)
    kernel_copyout(sbl.g_sbl_kernel_data_base + sbl.g_sbl_kernel_offset_dmpdpi, DMPDPI, 8)

    sbl.g_sbl_dmap_base = (DMPDPI << 30) | (DMPML4I << 39) | 0xFFFF800000000000
end


function sbl.sceSblServiceRequest(sock, msg_header, in_buf, out_buf)
    local mailbox_addr = sbl.g_sbl_kernel_data_base + sbl.g_sbl_kernel_offset_mailbox_base
    local mailbox_to_bitmap = 0
    local message_id = 0

    kernel_copyout(sbl.g_sbl_kernel_data_base + sbl.g_sbl_kernel_offset_g_message_id, message_id, 8)

    if message_id == 0 then
        message_id = 0x414100
    end

    msg_header.message_id = message_id
    message_id = message_id + 1

    kernel_copyin(message_id, sbl.g_sbl_kernel_data_base + sbl.g_sbl_kernel_offset_g_message_id, 8)

    sbl.SOCK_LOG(sock, "sceSblServiceRequest: retrieved message id (0x%x)\n", msg_header.message_id)

    local mailbox_metadata = {
        message_id = msg_header.message_id,
        unk_08h = 0,
        unk_10h = 0
    }

    mailbox_to_bitmap = mailbox_to_bitmap | (1 << 14)

    local err = sbl.sceSblDriverSendMsg(sock, msg_header, in_buf)
    if err ~= 0 then
        sbl.SOCK_LOG(sock, "sceSblServiceRequest: sceSblDriverSendMsg() failed: %d\n", err)
        sbl.DumpHex(sock, in_buf)
        return err
    end

    return 0
end
 
function sbl.sceSblDriverSendMsg(sock, msg_header, in_buf)
    local mmio_space = sbl.g_sbl_dmap_base + 0xE0500000
    local mailbox_base = sbl.g_sbl_kernel_data_base + sbl.g_sbl_kernel_offset_mailbox_base
    local mailbox_addr = mailbox_base + (0x800 * (0x10 + 14))
    
    local cmd = msg_header.cmd << 8
    local mailbox_pa = mailbox_addr --  `pmap_kextract`

    sbl.SOCK_LOG(sock, "sceSblDriverSendMsg: Writing to mailbox\n")
    
    return 0
end

function sbl.pmap_kextract(sock, va)
    local dmpml4i = sbl.g_sbl_kernel_offset_dmpml4i
    local dmpdpi = sbl.g_sbl_kernel_offset_dmpdpi
    local pml4pml4i = sbl.g_sbl_kernel_offset_pml4pml4i
    local dmap = (dmpdpi << 30) | (dmpml4i << 39) | 0xFFFF800000000000
    local dmap_end = ((dmpml4i + 1) << 39) | 0xFFFF800000000000

    if dmap <= va and dmap_end > va then
        return va - dmap
    end

    return va
end

function sbl.sceSblDriverSendMsgAnytime(sock, msg_header, in_buf, out_buf)
    sbl.SOCK_LOG(sock, "sceSblDriverSendMsgAnytime: called\n")
    return -1
end

function sbl.sceSblDriverSendMsgPol(sock, msg_header, in_buf, out_buf)
    sbl.SOCK_LOG(sock, "sceSblDriverSendMsgPol: called\n")
    return -1
end

function sbl.sceSblDriverSendMsg(sock, msg_header, in_buf)
    sbl.SOCK_LOG(sock, "sceSblDriverSendMsg: called\n")
    return -1
end

return sbl