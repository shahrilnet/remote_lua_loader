local self = {}


self.PAGE_SHIFT = 0x0000000C

self.SELF_ORBIS_MAGIC    = 0x1D3D154F
self.SELF_PROSPERO_MAGIC = 0xEEF51454


function self.SELF_SEGMENT_ID(x) return (x.flags >> 20) end
function self.SELF_SEGMENT_IS_ENCRYPTED(x) return ((x.flags & (1 << 1)) ~= 0) end
function self.SELF_SEGMENT_IS_SIGNED(x) return ((x.flags & (1 << 2)) ~= 0) end
function self.SELF_SEGMENT_IS_COMPRESSED(x) return ((x.flags & (1 << 3)) ~= 0) end
function self.SELF_SEGMENT_HAS_BLOCKS(x) return ((x.flags & (1 << 11)) ~= 0) end
function self.SELF_SEGMENT_HAS_DIGESTS(x) return ((x.flags & (1 << 16)) ~= 0) end
function self.SELF_SEGMENT_HAS_BLOCKINFO(x) return ((x.flags & (1 << 17)) ~= 0) end
function self.SELF_SEGMENT_BLOCK_SIZE(x) return (1 << (((x.flags >> 12) & 0xF) + self.PAGE_SHIFT)) end


self.sce_self_header = {
    magic = 0,
    version = 0,
    mode = 0,
    endian = 0,
    attributes = 0,
    key_type = 0,
    header_size = 0,
    metadata_size = 0,
    file_size = 0,
    segment_count = 0,
    flags = 0,
    pad_2 = {}
}


self.sce_self_segment_header = {
    flags = 0,
    offset = 0,
    compressed_size = 0,
    uncompressed_size = 0
}


self.sce_self_block_info = {
    offset = 0,
    len = 0
}

return self