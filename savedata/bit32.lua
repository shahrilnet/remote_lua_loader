
-- Copyright (C) 2014-2015  Nathanaël Courant (a.k.a. Nore/Novatux) (nore@mesecons.net)

-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:

-- The above copyright notice and this permission notice shall be included in
-- all copies or substantial portions of the Software.

-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
-- THE SOFTWARE.
--
-- source - https://github.com/minetest-mods/turtle/blob/master/bit32.lua
--

bit32 = {}

bit32.N = 32
bit32.P = 2 ^ bit32.N

function bit32.bnot(x)
    x = x % bit32.P
    return bit32.P - 1 - x
end

function bit32.band(...)
    local args = {...}
    local result = args[1] or 0
    for i = 2, #args do
        local x, y = result, args[i]
        -- Common usecases, they deserve to be optimized
        if y == 0xff then
            result = x % 0x100
        elseif y == 0xfff then
            result = x % 0x1000
        elseif y == 0xffff then
            result = x % 0x10000
        elseif y == 0xffffffff then
            result = x % 0x100000000
        else
            x, y = x % bit32.P, y % bit32.P
            result = 0
            local p = 1
            for j = 1, bit32.N do
                local a, b = x % 2, y % 2
                x, y = math.floor(x / 2), math.floor(y / 2)
                if a + b == 2 then
                    result = result + p
                end
                p = 2 * p
            end
        end
    end
    return result
end

function bit32.bor(...)
    local args = {...}
    local result = args[1] or 0
    for i = 2, #args do
        local x, y = result, args[i]
        -- Common usecases, they deserve to be optimized
        if y == 0xff then
            result = x - (x%0x100) + 0xff
        elseif y == 0xffff then
            result = x - (x%0x10000) + 0xffff
        elseif y == 0xffffffff then
            result = 0xffffffff
        else
            x, y = x % bit32.P, y % bit32.P
            result = 0
            local p = 1
            for j = 1, bit32.N do
                local a, b = x % 2, y % 2
                x, y = math.floor(x / 2), math.floor(y / 2)
                if a + b >= 1 then
                    result = result + p
                end
                p = 2 * p
            end
        end
    end
    return result
end

function bit32.bxor(...)
    local args = {...}
    local result = args[1] or 0
    for i = 2, #args do
        local x, y = result, args[i]
        x, y = x % bit32.P, y % bit32.P
        result = 0
        local p = 1
        for j = 1, bit32.N do
            local a, b = x%2, y%2
            x, y = math.floor(x/2), math.floor(y/2)
            if a + b == 1 then
                result = result + p
            end
            p = 2 * p
        end
    end
    return result
end

function bit32.lshift(x, s_amount)
    if math.abs(s_amount) >= bit32.N then return 0 end
    x = x % bit32.P
    if s_amount < 0 then
        return math.floor(x * (2 ^ s_amount))
    else
        return (x * (2 ^ s_amount)) % bit32.P
    end
end

function bit32.rshift(x, s_amount)
    if math.abs(s_amount) >= bit32.N then return 0 end
    x = x % bit32.P
    if s_amount > 0 then
        return math.floor(x * (2 ^ - s_amount))
    else
        return (x * (2 ^ -s_amount)) % bit32.P
    end
end

function bit32.arshift(x, s_amount)
    if math.abs(s_amount) >= bit32.N then return 0 end
    x = x % bit32.P
    if s_amount > 0 then
        local add = 0
        if x >= bit32.P/2 then
            add = bit32.P - 2 ^ (bit32.N - s_amount)
        end
        return math.floor(x * (2 ^ -s_amount)) + add
    else
        return (x * (2 ^ -s_amount)) % bit32.P
    end
end
