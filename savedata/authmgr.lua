local authmgr = {}
local self = require "self"
local sbl = require "sbl"

authmgr.SBL_FUNC_AUTHMGR_VERIFY_HEADER      = 0x01
authmgr.SBL_FUNC_AUTHMGR_LOAD_SELF_SEGMENT  = 0x02
authmgr.SBL_FUNC_AUTHMGR_FINALIZE           = 0x05
authmgr.SBL_FUNC_AUTHMGR_LOAD_SELF_BLOCK    = 0x06


authmgr.self_block_segment = {
    data = nil,
    size = 0,
    extents = {},
    digests = {},
    block_count = 0
}


authmgr.sbl_authmgr_verify_header = {
    function_id = 0,
    res = 0,
    self_header_pa = 0,
    self_header_size = 0,
    unk14 = {},
    service_id = 0,
    auth_id = 0,
    unk28 = {},
    unk38 = 0,
    pad = {}
}

authmgr.sbl_authmgr_load_segment = {
    function_id = 0,
    res = 0,
    chunk_table_pa = 0,
    segment_index = 0,
    is_block_table = 0x01,
    unk16 = 0,
    unk18 = {},
    service_id = 0,
    pad = {}
}

authmgr.sbl_authmgr_load_block = {
    function_id = 0,
    res = 0,
    out_pa = 0,
    in_pa = 0,
    unk18 = 0,
    unk20 = 0,
    unk28 = 0,
    aligned_size = 0,
    size = 0,
    unk38 = 0,
    segment_index = 0,
    block_index = 0,
    service_id = 0,
    digest = {},
    ext_info = {},
    is_compressed = 0,
    unk72 = 0,
    is_plain_elf = 0,
    pad = {}
}

authmgr.sbl_authmgr_finalize_ctx = {
    function_id = 0,
    res = 0,
    context_id = 0,
    pad = {}
}

authmgr.sbl_chunk_table_header = {
    first_pa = 0,
    data_size = 0,
    used_entries = 0,
    unk18 = 0
}

authmgr.sbl_chunk_table_entry = {
    pa = 0,
    size = 0
}

function authmgr.sceSblAuthMgrSmFinalize(sock, authmgr_handle, context_id)
    local msg = {
        cmd = 6,
        query_len = 0x80,
        recv_len = 0x80,
        message_id = 0,
        to_ret = authmgr_handle
    }

    local finalize = {
        function_id = authmgr.SBL_FUNC_AUTHMGR_FINALIZE,
        context_id = context_id
    }

    return sbl.sceSblServiceRequest(sock, msg, finalize, finalize)
end

function authmgr.sceSblAuthMgrVerifyHeader(sock, authmgr_handle, header_pa, header_len)
    local msg = {
        cmd = 6,
        query_len = 0x80,
        recv_len = 0x80,
        message_id = 0,
        to_ret = authmgr_handle
    }

    local verify = {
        function_id = authmgr.SBL_FUNC_AUTHMGR_VERIFY_HEADER,
        self_header_pa = header_pa,
        self_header_size = header_len,
        auth_id = 0
    }

    local err = sbl.sceSblServiceRequest(sock, msg, verify, verify)
    if err ~= 0 then return err end

    return verify.service_id
end


function authmgr.sceSblAuthMgrSmLoadSelfSegment(sock, authmgr_handle, service_id, chunk_table_pa, segment_index)
    local msg = {
        cmd = 6,
        query_len = 0x80,
        recv_len = 0x80,
        message_id = 0,
        to_ret = authmgr_handle
    }

    local load = {
        function_id = authmgr.SBL_FUNC_AUTHMGR_LOAD_SELF_SEGMENT,
        chunk_table_pa = chunk_table_pa,
        segment_index = segment_index,
        is_block_table = 0x01,
        service_id = service_id
    }

    return sbl.sceSblServiceRequest(sock, msg, load, load)
end


function authmgr.sceSblAuthMgrSmLoadSelfBlock(sock, authmgr_handle, service_id, in_pa, out_pa, segment, segment_idx, block_segment, block_idx)
    local msg = {
        cmd = 6,
        query_len = 0x80,
        recv_len = 0x80,
        message_id = 0,
        to_ret = authmgr_handle
    }

    local load = {
        function_id = authmgr.SBL_FUNC_AUTHMGR_LOAD_SELF_BLOCK,
        out_pa = out_pa,
        in_pa = in_pa,
        unk18 = in_pa,
        service_id = service_id,
        segment_index = segment_idx,
        block_index = block_idx,
        is_compressed = 0,
        is_plain_elf = 0,
        res = -1
    }

    
    load.digest = block_segment.digests[block_idx]
    load.ext_info = block_segment.extents[block_idx]

    local size_one, size_two
    if self.SELF_SEGMENT_IS_COMPRESSED(segment) then
        size_one = block_segment.extents[block_idx].len & ~0xF
        size_two = size_one - (block_segment.extents[block_idx].len & 0xF)
    else
        size_one = size_two = block_segment.extents[block_idx].len
    end

    load.aligned_size = size_two
    load.size = size_one

    local res = sbl.sceSblServiceRequest(sock, msg, load, load)
    if res == 0 and load.res ~= 0 then
        res = load.res
    end

    return res
end

return authmgr