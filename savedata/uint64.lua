
--
-- uint64 class
--
-- constructor accepts:
-- 1) uint64 instance
-- 2) hex value in string ("0xaabb")
-- 3) lua number
--
-- note: from llm and refined over time. might have some bugs
--

uint64 = {}
uint64.__index = uint64

setmetatable(uint64, {
    __call = function(_, v) -- make class callable
        return uint64:new(v)
    end
})

function is_uint64(v)
    return type(v) == "table" and v.h and v.l and true or false
end

function ub8(n) 
    return uint64(n):pack() 
end

function hex(v)
    if is_uint64(v) then
        return tostring(v)
    elseif type(v) == "number" then
        return string.format("0x%x", v)
    else
        errorf("hex: unknown type (%s)", type(v))
    end
end

function uint64:new(v)

    local self = setmetatable({}, uint64)

    if is_uint64(v) then
        self.h, self.l = v.h, v.l
    elseif type(v) == "number" then
        self.h, self.l = math.floor(v / 2^32), v % 2^32
    elseif type(v) == "string" then
        if v:sub(1, 2):lower() == "0x" then  -- init from hexstring
            v = v:sub(3):gsub("^0+", ""):upper()
            assert(#v <= 16, string.format("uint64:new: hex string too long for uint64 (%s)", v))
            v = string.rep("0", 16 - #v) .. v  -- pad with leading zeros
            self.h = tonumber(v:sub(1, 8), 16) or 0
            self.l = tonumber(v:sub(9, 16), 16) or 0
        else
            local num = tonumber(v)  -- assume its normal number
            assert(num, string.format("uint64:new: invalid decimal string for uint64 (%s)", v))
            self.h, self.l = math.floor(num / 2^32), num % 2^32
        end
    else
        errorf("uint64:new: invalid type passed to constructor (%s)", type(v))
    end

    return self
end

function uint64:__tostring()
    local hex = string.format("%x%08x", self.h, self.l):gsub("^0+", "")
    return "0x" .. (hex == "" and "0" or hex)
end

function uint64:tonumber()
    if self.h >= 0x80000000 then -- for negative number
        return -(bit32.bnot(self.h) * 2^32 + bit32.bnot(self.l) + 1)
    else
        return self.h * 2^32 + self.l
    end
end

function uint64:pack()
    return string.char(
        self.l % 256,
        bit32.rshift(self.l, 8) % 256,
        bit32.rshift(self.l, 16) % 256,
        bit32.rshift(self.l, 24) % 256,
        self.h % 256,
        bit32.rshift(self.h, 8) % 256,
        bit32.rshift(self.h, 16) % 256,
        bit32.rshift(self.h, 24) % 256
    )
end

function uint64.unpack(str)
    if not (type(str) == "string" and #str == 8 or #str == 4) then
        error("uint64.unpack: input string must be 8 or 4 length size")
    end
    local l = str:byte(1) + bit32.lshift(str:byte(2), 8) 
        + bit32.lshift(str:byte(3), 16) + bit32.lshift(str:byte(4), 24)
    local h = #str == 8 and (str:byte(5) + bit32.lshift(str:byte(6), 8) 
        + bit32.lshift(str:byte(7), 16) + bit32.lshift(str:byte(8), 24)) or 0
    return uint64({h = h, l = l})
end

-- note: comparison ops only work if both are same type

function uint64:__eq(v)
    v = uint64(v)
    return self.h == v.h and self.l == v.l
end

function uint64:__lt(v)
    v = uint64(v)
    return self.h < v.h or (self.h == v.h and self.l < v.l)
end

function uint64:__le(v)
    v = uint64(v)
    return self.h < v.h or (self.h == v.h and self.l <= v.l)
end

function uint64:__add(v)
    v = uint64(v)
    local l = self.l + v.l
    local h = self.h + v.h + (l >= 2^32 and 1 or 0)
    return uint64({h = h % 2^32, l = l % 2^32})
end

function uint64:__sub(v)
    v = uint64(v)
    local l = self.l - v.l
    local h = self.h - v.h - (l < 0 and 1 or 0)
    return uint64({h = (h + 2^32) % 2^32, l = (l + 2^32) % 2^32})
end

function uint64:__mul(v)
    v = uint64(v)
    local ah, al, bh, bl = self.h, self.l, v.h, v.l
    local h = ah * bl + al * bh
    local l = al * bl
    return uint64({h = (h + bit32.rshift(l, 32)) % 2^32, l = l % 2^32})
end

function uint64:divmod(v)
    v = uint64(v)
    if v.h == 0 and v.l == 0 then error("division by zero") end
    local q, r = uint64(0), uint64(0)
    for i = 63, 0, -1 do
        r = r:lshift(1)
        if bit32.rshift(self.h, i % 32) % 2 == 1 or (i < 32 and bit32.rshift(self.l, i) % 2 == 1) then
            r = r + 1
        end
        if r >= v then
            r = r - v
            q = q + uint64(1):lshift(i)
        end
    end
    return q, r
end

function uint64:__div(v) return select(1, self:divmod(v)) end
function uint64:__mod(v) return select(2, self:divmod(v)) end

function uint64:lshift(n)
    if n >= 64 then return uint64(0) end
    if n >= 32 then
        return uint64({h = bit32.lshift(self.l, n - 32), l = 0})
    else
        local h = bit32.bor(bit32.lshift(self.h, n), bit32.rshift(self.l, 32 - n))
        local l = bit32.lshift(self.l, n)
        return uint64({h = h, l = l})
    end
end

function uint64:rshift(n)
    if n >= 64 then return uint64(0) end
    if n >= 32 then
        return uint64({h = 0, l = bit32.rshift(self.h, n - 32)})
    else
        local h = bit32.rshift(self.h, n)
        local l = bit32.bor(bit32.rshift(self.l, n), bit32.lshift(self.h % (2^n), 32 - n))
        return uint64({h = h, l = l})
    end
end

function uint64:bxor(v)
    v = uint64(v)
    local h = bit32.bxor(self.h, v.h)
    local l = bit32.bxor(self.l, v.l)
    return uint64({h = h, l = l})
end

function uint64:band(v)
    v = uint64(v)
    local h = bit32.band(self.h, v.h)
    local l = bit32.band(self.l, v.l)
    return uint64({h = h, l = l})
end

function uint64:bor(v)
    v = uint64(v)
    local h = bit32.bor(self.h, v.h)
    local l = bit32.bor(self.l, v.l)
    return uint64({h = h, l = l})
end

function uint64:bnot()
    local h = bit32.bnot(self.h)
    local l = bit32.bnot(self.l)
    return uint64({h = h, l = l})
end
