
--
-- memory class
--
-- initially uses lua weak r/w primitives
-- once native handler is registered, this class will be upgraded to arbitrary r/w primitives
--

memory = {}

-- this fn will always return zeroed buffer 
function memory.alloc(size)
    if native_invoke then
        return native.fcall(libc_addrofs.calloc, size, 1)
    else
        -- compensate for write corruption by lua primitive
        size = align_16(size + 8)
        return bump.alloc(size)
    end
end

function memory.read_buffer(addr, size)
    assert(addr and size)
    if native_invoke then
        return native.read_buffer(addr, size)
    else
        return lua.read_buffer(addr, size)
    end
end

function memory.read_dword(addr)
    local value = memory.read_buffer(addr, 4)
    return value and #value == 4 and uint64.unpack(value) or nil 
end

function memory.read_qword(addr)
    local value = memory.read_buffer(addr, 8)
    return value and #value == 8 and uint64.unpack(value) or nil 
end

function memory.read_multiple_qwords(addr, count)
    local qwords = {}
    local buffer = memory.read_buffer(addr, count*8)
    for i=0,(#buffer/8)-1 do
        table.insert(qwords, uint64.unpack(buffer:sub(i*8+1, i*8+8)))
    end
    return qwords
end

function memory.write_buffer(dest, buffer)
    assert(native_invoke and dest and buffer)
    native.write_buffer(dest, buffer)
end

function memory.write_byte(dest, value)
    memory.write_buffer(dest, ub8(value):sub(1,1))
end

function memory.write_word(dest, value)
    memory.write_buffer(dest, ub8(value):sub(1,2))
end

function memory.write_dword(dest, value)
    memory.write_buffer(dest, ub8(value):sub(1,4))
end

function memory.write_qword(dest, value)
    assert(dest and value)
    if native_invoke then
        memory.write_buffer(dest, ub8(value))
    else
        -- weak primitive because of data corruption
        lua.write_qword(dest, value)
    end
end

function memory.write_multiple_qwords(addr, list)
    for i,v in ipairs(list) do
        memory.write_qword(addr+8*(i-1), list[i])
    end
end

function memory.memcpy(dest, src, size)
    size = uint64(size):tonumber()
    if native_invoke then
        memory.write_buffer(dest, memory.read_buffer(src, size))
    else
        assert(size % 8 == 0)
        memory.write_multiple_qwords(dest, memory.read_multiple_qwords(src, size / 8))
    end
end

function memory.hex_dump(addr, size)
    size = size or 0x40
    return hex_dump(memory.read_buffer(addr, size), addr)
end

function memory.read_null_terminated_string(addr)
    local result = ""
    while true do
        local chunk = memory.read_buffer(addr, 0x50)
        local null_pos = chunk:find("\0")
        if null_pos then 
            return result .. chunk:sub(1, null_pos - 1)
        end
        result = result .. chunk
        addr = addr + #chunk
    end
    return result
end