
--
-- checksum functions
--

function crc32_table()
    local tbl = {}
    for i = 0, 255 do
        local crc = i
        for _ = 1, 8 do
            if bit32.band(crc, 1) == 1 then
                crc = bit32.bxor(0xEDB88320, bit32.rshift(crc, 1))
            else
                crc = bit32.rshift(crc, 1)
            end
        end
        tbl[i] = crc
    end
    return tbl
end

crc32_tbl = crc32_table()

function crc32(data)
    local crc = 0xFFFFFFFF
    for i = 1, #data do
        local byte = data:byte(i)
        local index = bit32.band(bit32.bxor(crc, byte), 0xFF)
        crc = bit32.bxor(crc32_tbl[index], bit32.rshift(crc, 8))
    end
    return bit32.bxor(crc, 0xFFFFFFFF)
end
