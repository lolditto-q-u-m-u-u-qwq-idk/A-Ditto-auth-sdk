local t9k = tick()
print(
    [==[
A-Ditto Auth SDK                                                 
__     __      ____  
\ \   / /      |___ \ 
 \ \ / /         __) |
  \ V /         / __/ 
   \_/         |_____|
   
 ____                   
|  _ \    _ __     ___  
| |_) |  | '__|   / _ \ 
|  __/   | |     | (_) |
|_|      |_|      \___/ 

By continuing you agree to the
User Agreement: https://a-ditto.xyz/user-agreement
Privacy Policy: https://a-ditto.xyz/privacy-policy
Learn more at https://a-ditto.xyz/
]==]
)
local eR4r = function(wD1, mode)
    task.spawn(
        function()
            local LocalPlayer = game.Players.LocalPlayer
            LocalPlayer:Kick(wD1)
        end
    )
    task.wait(9)
    LPH_CRASH()
end

if not getfenv().ADittoKey or #getfenv().ADittoKey < 1 then
    return eR4r("You haven't entered a key yet(Error Code: A-Ditto-C COOL)")
end

local uBqea = function(...)
    local Fh = 0
    for Xb = 1, math.random(1, 3) do
        Fh = math.random()
    end
    return math.random(...)
end
local YqU = (function()
    local eLq, NwpS = bit32.rshift, bit32.band
    local oDozT = "0123456789abcdef"
    return function(Gns)
        local vP = string.byte(Gns)
        if not vP then
            return "00"
        end
        local nCj, Ztq = eLq(vP, 4), NwpS(vP, 15)
        return oDozT:sub(nCj + 1, nCj + 1) .. oDozT:sub(Ztq + 1, Ztq + 1)
    end
end)()
local rFvB = function(zYx)
    local QopL = #zYx
    for i = 1, (QopL % 7 == 0 and 2 or (QopL % 7 >= 2 and QopL % 7 or 2)) do
        for sF = 1, QopL do
            local pM = uBqea(sF, QopL)
            zYx[sF], zYx[pM] = zYx[pM], zYx[sF]
        end
    end
    return zYx
end
local kRta = {}
for iW = 1, 10 do
    kRta[iW] = {}
    local hHka = kRta[iW]
    for oEw = 1, uBqea(5, 10) do
        hHka.val = uBqea(1, 255)
        hHka.sub = {}
        hHka = hHka.sub
    end
end
local tReWq = {}
local vU = 0
local yA = uBqea(200, 255) + 25
for jO = 1, yA do
    local fslkfvdjl = uBqea(0, 255)
    if 0 <= fslkfvdjl and fslkfvdjl <= 255 then
        tReWq[#tReWq + 1] = fslkfvdjl
    else
        LPH_CRASH()
    end
end
rFvB(tReWq)
local zFv = 0
for aL = 1, #tReWq do
    zFv = zFv + tReWq[aL]
end
local tYp = zFv / #tReWq
local fLq = 0
for aL = 1, #tReWq do
    fLq = fLq + (tReWq[aL] - tYp) ^ 2
end
local uRk = fLq / #tReWq
if tYp < 100 or tYp > 150 then
    LPH_CRASH()
end
local nBn, bNsT, bNsS = 16, {}, 256 / 16
for xI = 1, nBn do
    bNsT[xI] = 0
end
for xI = 1, #tReWq do
    local vAl = tReWq[xI]
    local bNx = math.floor(vAl / bNsS) + 1
    bNsT[bNx] = bNsT[bNx] + 1
end
local eXfQ, cXsq = #tReWq / nBn, 0
for xI = 1, nBn do
    cXsq = cXsq + (bNsT[xI] - eXfQ) ^ 2 / eXfQ
end
if cXsq > 55 or cXsq < 1.5 then
    LPH_CRASH()
end
local dFsm = 0
for xI = 1, #tReWq - 1 do
    dFsm = dFsm + math.abs(tReWq[xI + 1] - tReWq[xI])
end
local aVgd = dFsm / (#tReWq - 1)
if aVgd < 40 or aVgd > 120 then
    LPH_CRASH()
end
if uRk < 900 or uRk > 25000 then
    LPH_CRASH()
end
local nBv = {a = 1, b = 2, c = 3, d = 4, e = 5}
local wXo, bA, iOlp, qVp = 0, 0, 0, 0
for Pz, Ds in pairs(nBv) do
    wXo = wXo + 1
    iOlp = bit32.bxor(iOlp, string.byte(Pz))
    iOlp = bit32.bxor(iOlp, Ds)
end
for Pz, Ds in next, nBv do
    bA = bA + 1
    qVp = bit32.bxor(qVp, string.byte(Pz))
    qVp = bit32.bxor(qVp, Ds)
end
if wXo ~= 5 or bA ~= 5 or iOlp ~= qVp then
    LPH_CRASH()
end
vU = bit32.bxor(vU, bit32.rrotate(iOlp, wXo % 8))
local lEnke = tReWq[uBqea(1, #tReWq)] % 10 + 5
for xI = 1, #tReWq do
    tReWq[xI] = bit32.bxor(tReWq[xI], vU)
end
local cSone = 0
for xI = 1, #tReWq - 1 do
    cSone = bit32.bxor(cSone, tReWq[xI])
end
tReWq[#tReWq] = cSone
local pOs = #tReWq
local VaL = tReWq[pOs]
local CAl = 0
for xI = 1, pOs - 1 do
    CAl = bit32.bxor(CAl, tReWq[xI])
end
if CAl ~= VaL then
    LPH_CRASH()
end
rFvB(tReWq)
local fINnC = ""
for xI = 1, 25 do
    fINnC = fINnC .. YqU(string.char(tReWq[xI]))
end
local rSfiV = fINnC
local GEnFn = function()
    local fNs = {}
    local sTAtv = uBqea(100, 255)
    local mAGic = uBqea(256, 300)
    local tMPls = {
        function(sElF, nN)
            sTAtv = bit32.bxor(sTAtv, nN)
            if sTAtv == mAGic then
                LPH_CRASH()
            end
            return sTAtv
        end,
        function(sElF, nN)
            if uBqea(2, 100) == 1 then
                LPH_CRASH()
            end
            return sElF[uBqea(1, #sElF)](sElF, nN - 1)
        end,
        function(sElF, nN)
            local dE, mDe = nN, uBqea(5, 10)
            local function rR(sS, cC)
                if cC > mDe then
                    return cC
                end
                return rR(sS, cC + 1)
            end
            return rR(sElF, 0)
        end
    }
    for xI = 1, uBqea(10, 20) do
        fNs[xI] = tMPls[uBqea(1, #tMPls)]
    end
    return fNs
end
local NsyFN = GEnFn()
pcall(
    function()
        for xI = 1, uBqea(10, 20) do
            NsyFN[uBqea(1, #NsyFN)](NsyFN, uBqea(5, 15))
        end
    end
)
local lGfV, eXPEc = nil, "..."
for xI = 1, uBqea(11, 255) % 30 do
    local sPc, kOp =
        pcall(
        function()
            task.spawn(
                function()
                    local aA = 1
                    local bB = print
                end
            )
            bB(aA)
        end
    )
    if sPc then
        LPH_CRASH()
    end
end
for xI = 1, uBqea(11, 255) % 60 do
    local sPc, kOp =
        pcall(
        function()
        end
    )
    if sPc ~= true then
        LPH_CRASH()
    end
end
if lGfV then
    LPH_CRASH()
end
for xI = 1, uBqea(11, 255) % 40 do
    task.spawn(
        function()
            wKdk = 1
        end
    )
end
for xI = 1, uBqea(11, 255) % 50 do
    task.spawn(
        function()
            lGfV = eXPEc
        end
    )
    if lGfV and lGfV ~= eXPEc then
        LPH_CRASH()
    end
end
local bit_band = bit32.band
local bit_bxor = bit32.bxor
local bit_rrotate = bit32.rrotate
local bit_lshift = bit32.lshift
local bit_rshift = bit32.rshift
local bit_bor = bit32.bor
local bit_bnot = bit32.bnot
local string_char = string.char
local string_byte = string.byte
local bit_lrotate = bit32.lrotate
local IV = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
}

local SIGMA_FLAT = {
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    14,
    10,
    4,
    8,
    9,
    15,
    13,
    6,
    1,
    12,
    0,
    2,
    11,
    7,
    5,
    3,
    11,
    8,
    12,
    0,
    5,
    2,
    15,
    13,
    10,
    14,
    3,
    6,
    7,
    1,
    9,
    4,
    7,
    9,
    3,
    1,
    13,
    12,
    11,
    14,
    2,
    6,
    5,
    10,
    4,
    0,
    15,
    8,
    9,
    0,
    5,
    7,
    2,
    4,
    10,
    15,
    14,
    1,
    11,
    12,
    6,
    8,
    3,
    13,
    2,
    12,
    6,
    10,
    0,
    11,
    8,
    3,
    4,
    13,
    7,
    5,
    15,
    14,
    1,
    9,
    12,
    5,
    1,
    15,
    14,
    13,
    4,
    10,
    0,
    7,
    6,
    3,
    9,
    2,
    8,
    11,
    13,
    11,
    7,
    14,
    12,
    1,
    3,
    9,
    5,
    0,
    15,
    4,
    8,
    6,
    2,
    10,
    6,
    15,
    14,
    9,
    11,
    3,
    0,
    8,
    12,
    2,
    13,
    7,
    1,
    4,
    10,
    5,
    10,
    2,
    8,
    4,
    7,
    6,
    1,
    5,
    15,
    11,
    9,
    14,
    3,
    12,
    13,
    0
}

local string_rep = function(s, n)
    if n <= 0 then
        return ""
    end
    local result = ""
    for _ = 1, n do
        result = result .. s
    end
    return result
end
local table_concat = function(tbl)
    local result = ""
    for i = 1, #tbl do
        if tbl[i] then
            result = result .. tbl[i]
        end
    end
    return result
end
local string_sub = function(s, i, j)
    if type(s) ~= "string" then
        return ""
    end
    local len = #s
    i = i or 1
    j = j or len
    if i < 0 then
        i = len + i + 1
    end
    if j < 0 then
        j = len + j + 1
    end
    if i < 1 then
        i = 1
    end
    if j > len then
        j = len
    end
    if i > j then
        return ""
    end
    local result = {}
    for k = i, j do
        result[#result + 1] = string_char(string_byte(s, k))
    end
    return table_concat(result)
end
local table_insert = function(t, pos_or_va, val)
    if value == nil then
        local value = pos_or_va
        t[#t + 1] = val
    else
        local pos = pos_or_va
        for i = #t, pos, -1 do
            t[i + 1] = t[i]
        end
        t[pos] = val
    end
end

local BLOCK_BYTES = 64
local HEX_CHARS = "0123456789abcdef"
local to_bytes_le = function(n)
    return string_char(
        bit_band(n, 0xff),
        bit_band(bit_rshift(n, 8), 0xff),
        bit_band(bit_rshift(n, 16), 0xff),
        bit_band(bit_rshift(n, 24), 0xff)
    )
end
local from_bytes_le = function(s, i)
    i = i or 1
    local b1, b2, b3, b4 = string_byte(s, i, i + 3)
    return bit_bor(b1 or 0, bit_lshift(b2 or 0, 8), bit_lshift(b3 or 0, 16), bit_lshift(b4 or 0, 24))
end
local compress = function(h, t_low, t_high, block, is_last_block)
    local v = {}
    local m = {}
    for i = 1, 8 do
        v[i] = h[i]
    end
    for i = 1, 8 do
        v[i + 8] = IV[i]
    end
    v[13] = bit_bxor(v[13], t_low)
    v[14] = bit_bxor(v[14], t_high)
    if is_last_block then
        v[15] = bit_bnot(v[15])
    end
    for i = 1, 16 do
        m[i] = from_bytes_le(block, (i - 1) * 4 + 1)
    end
    for r = 0, 9 do
        local s_offset = r * 16

        local va, vb, vc, vd = v[1], v[5], v[9], v[13]
        local x, y = m[SIGMA_FLAT[s_offset + 1] + 1], m[SIGMA_FLAT[s_offset + 2] + 1]
        va = bit_band(va + vb + x, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 16)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 12)
        va = bit_band(va + vb + y, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 8)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 7)
        v[1], v[5], v[9], v[13] = va, vb, vc, vd

        local va, vb, vc, vd = v[2], v[6], v[10], v[14]
        local x, y = m[SIGMA_FLAT[s_offset + 3] + 1], m[SIGMA_FLAT[s_offset + 4] + 1]
        va = bit_band(va + vb + x, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 16)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 12)
        va = bit_band(va + vb + y, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 8)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 7)
        v[2], v[6], v[10], v[14] = va, vb, vc, vd

        local va, vb, vc, vd = v[3], v[7], v[11], v[15]
        local x, y = m[SIGMA_FLAT[s_offset + 5] + 1], m[SIGMA_FLAT[s_offset + 6] + 1]
        va = bit_band(va + vb + x, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 16)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 12)
        va = bit_band(va + vb + y, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 8)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 7)
        v[3], v[7], v[11], v[15] = va, vb, vc, vd

        local va, vb, vc, vd = v[4], v[8], v[12], v[16]
        local x, y = m[SIGMA_FLAT[s_offset + 7] + 1], m[SIGMA_FLAT[s_offset + 8] + 1]
        va = bit_band(va + vb + x, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 16)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 12)
        va = bit_band(va + vb + y, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 8)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 7)
        v[4], v[8], v[12], v[16] = va, vb, vc, vd

        local va, vb, vc, vd = v[1], v[6], v[11], v[16]
        local x, y = m[SIGMA_FLAT[s_offset + 9] + 1], m[SIGMA_FLAT[s_offset + 10] + 1]
        va = bit_band(va + vb + x, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 16)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 12)
        va = bit_band(va + vb + y, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 8)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 7)
        v[1], v[6], v[11], v[16] = va, vb, vc, vd

        local va, vb, vc, vd = v[2], v[7], v[12], v[13]
        local x, y = m[SIGMA_FLAT[s_offset + 11] + 1], m[SIGMA_FLAT[s_offset + 12] + 1]
        va = bit_band(va + vb + x, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 16)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 12)
        va = bit_band(va + vb + y, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 8)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 7)
        v[2], v[7], v[12], v[13] = va, vb, vc, vd

        local va, vb, vc, vd = v[3], v[8], v[9], v[14]
        local x, y = m[SIGMA_FLAT[s_offset + 13] + 1], m[SIGMA_FLAT[s_offset + 14] + 1]
        va = bit_band(va + vb + x, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 16)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 12)
        va = bit_band(va + vb + y, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 8)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 7)
        v[3], v[8], v[9], v[14] = va, vb, vc, vd

        local va, vb, vc, vd = v[4], v[5], v[10], v[15]
        local x, y = m[SIGMA_FLAT[s_offset + 15] + 1], m[SIGMA_FLAT[s_offset + 16] + 1]
        va = bit_band(va + vb + x, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 16)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 12)
        va = bit_band(va + vb + y, 0xFFFFFFFF)
        vd = bit_rrotate(bit_bxor(vd, va), 8)
        vc = bit_band(vc + vd, 0xFFFFFFFF)
        vb = bit_rrotate(bit_bxor(vb, vc), 7)
        v[4], v[5], v[10], v[15] = va, vb, vc, vd
    end
    for i = 1, 8 do
        h[i] = bit_bxor(h[i], v[i], v[i + 8])
    end
end

local blake2s = function(message, mode, length, key)
    mode = mode or "hex"
    length = length or 256
    key = key or ""
    if type(length) ~= "number" or length % 8 ~= 0 then
        return nil
    end
    local length_bytes = length / 8
    if length_bytes <= 0 or length_bytes > 32 then
        return nil
    end
    if #key > 32 then
        return nil
    end
    if type(message) ~= "string" then
        return nil
    end
    local h = {}
    for i = 1, 8 do
        h[i] = IV[i]
    end
    local p0_keylen = bit_lshift(#key, 8)
    local p0 = bit_bor(length_bytes, p0_keylen, 0x01010000)
    h[1] = bit_bxor(h[1], p0)
    local stream = message
    if #key > 0 then
        local key_block = key .. string_rep("\0", BLOCK_BYTES - #key)
        stream = key_block .. message
    end
    local t_low, t_high = 0, 0
    local offset = 1
    local stream_len = #stream
    while offset <= stream_len - BLOCK_BYTES do
        local chunk = string_sub(stream, offset, offset + BLOCK_BYTES - 1)
        t_low = t_low + BLOCK_BYTES
        if t_low > 0xffffffff then
            t_low = bit_band(t_low, 0xffffffff)
            t_high = t_high + 1
        end
        compress(h, t_low, t_high, chunk, false)
        offset = offset + BLOCK_BYTES
    end
    local last_chunk = string_sub(stream, offset)
    local last_len = #last_chunk
    t_low = t_low + last_len
    if t_low > 0xffffffff then
        t_low = bit_band(t_low, 0xffffffff)
        t_high = t_high + 1
    end
    local padded_chunk = last_chunk .. string_rep("\0", BLOCK_BYTES - last_len)
    compress(h, t_low, t_high, padded_chunk, true)
    local raw_digest_parts = {}
    for i = 1, 8 do
        raw_digest_parts[i] = to_bytes_le(h[i])
    end
    local raw_digest = string_sub(table_concat(raw_digest_parts), 1, length_bytes)
    if mode == "byte" or mode == "raw" then
        return raw_digest
    else
        local hex_parts = {}
        for i = 1, length_bytes do
            local b = string_byte(raw_digest, i)
            local high = bit_rshift(b, 4)
            local low = bit_band(b, 0x0F)
            hex_parts[i] = string_sub(HEX_CHARS, high + 1, high + 1) .. string_sub(HEX_CHARS, low + 1, low + 1)
        end
        return table_concat(hex_parts)
    end
end

local hex_to_binary = function(hex_str)
    local n = #hex_str
    if n % 2 ~= 0 then
        return nil
    end
    local t = {}
    for i = 1, n, 2 do
        local byte = tonumber(hex_str:sub(i, i + 1), 16)
        if not byte then
            return nil
        end
        t[#t + 1] = string.char(byte)
    end
    return table_concat(t)
end

local kdf_blake2s_keyed = function(ikm, salt, info, length)
    local HASH_LEN = 32

    if type(length) ~= "number" or length > 255 * HASH_LEN then
        LPH_CRASH()
    end
    if #salt > HASH_LEN then
        salt = blake2s(salt, "raw", 256)
    end
    local prk = blake2s(ikm, "raw", 256, salt)
    local okm, T = "", ""
    local num_blocks = ((length + HASH_LEN - 1) - ((length + HASH_LEN - 1) % HASH_LEN)) / HASH_LEN
    for i = 1, num_blocks do
        T = blake2s(T .. info .. string.char(i), "raw", 256, prk)
        okm = okm .. T
    end
    return okm
end

local u32 = function(x)
    return bit_band(x, 0xFFFFFFFF)
end

local add64 = function(hi, lo, b)
    local new_lo = u32(lo + b)
    local carry = new_lo < lo and 1 or 0
    return u32(hi + carry), new_lo
end

local quarter_round = function(st, a, b, c, d)
    st[a] = u32(st[a] + st[b])
    st[d] = bit_bxor(st[d], st[a])
    st[d] = bit_lrotate(st[d], 16)
    st[c] = u32(st[c] + st[d])
    st[b] = bit_bxor(st[b], st[c])
    st[b] = bit_lrotate(st[b], 12)
    st[a] = u32(st[a] + st[b])
    st[d] = bit_bxor(st[d], st[a])
    st[d] = bit_lrotate(st[d], 8)
    st[c] = u32(st[c] + st[d])
    st[b] = bit_bxor(st[b], st[c])
    st[b] = bit_lrotate(st[b], 7)
end

local chacha20_block = function(key, nonce, counter)
    local st = {}

    st[1] = 0x61707865
    st[2] = 0x3320646e
    st[3] = 0x79622d32
    st[4] = 0x6b206574
    for i = 0, 7 do
        local off = 1 + i * 4
        st[5 + i] =
            bit_bor(
            bit_lshift(string_byte(key, off + 3), 24),
            bit_lshift(string_byte(key, off + 2), 16),
            bit_lshift(string_byte(key, off + 1), 8),
            string_byte(key, off)
        )
    end
    st[13] = counter
    st[14] =
        bit_bor(
        bit_lshift(string_byte(nonce, 4), 24),
        bit_lshift(string_byte(nonce, 3), 16),
        bit_lshift(string_byte(nonce, 2), 8),
        string_byte(nonce, 1)
    )
    st[15] =
        bit_bor(
        bit_lshift(string_byte(nonce, 8), 24),
        bit_lshift(string_byte(nonce, 7), 16),
        bit_lshift(string_byte(nonce, 6), 8),
        string_byte(nonce, 5)
    )
    st[16] =
        bit_bor(
        bit_lshift(string_byte(nonce, 12), 24),
        bit_lshift(string_byte(nonce, 11), 16),
        bit_lshift(string_byte(nonce, 10), 8),
        string_byte(nonce, 9)
    )

    local orig = {}
    for i = 1, 16 do
        orig[i] = st[i]
    end

    for round = 1, 10 do
        quarter_round(st, 1, 5, 9, 13)
        quarter_round(st, 2, 6, 10, 14)
        quarter_round(st, 3, 7, 11, 15)
        quarter_round(st, 4, 8, 12, 16)
        quarter_round(st, 1, 6, 11, 16)
        quarter_round(st, 2, 7, 12, 13)
        quarter_round(st, 3, 8, 9, 14)
        quarter_round(st, 4, 5, 10, 15)
    end

    for i = 1, 16 do
        st[i] = u32(st[i] + orig[i])
    end

    local out = {}
    for i = 1, 16 do
        local w = st[i]
        out[4 * i - 3] = string_char(bit_band(w, 0xFF))
        out[4 * i - 2] = string_char(bit_band(bit_rshift(w, 8), 0xFF))
        out[4 * i - 1] = string_char(bit_band(bit_rshift(w, 16), 0xFF))
        out[4 * i] = string_char(bit_band(bit_rshift(w, 24), 0xFF))
    end
    return table_concat(out)
end

local xor_bytes = function(a, b, len)
    local t = {}
    for i = 1, len do
        local x = bit_bxor(string_byte(a, i), string_byte(b, i))
        t[i] = string_char(x)
    end
    return table_concat(t)
end

local chacha20_crypt = function(key, nonce, counter, plaintext)
    local pt_len = #plaintext
    local ct = {}
    local pos = 1
    while pos <= pt_len do
        local block = chacha20_block(key, nonce, counter)
        local take = (64 < (pt_len - pos + 1)) and 64 or (pt_len - pos + 1)
        ct[#ct + 1] = xor_bytes(string_sub(plaintext, pos, pos + take - 1), string_sub(block, 1, take), take)
        pos = pos + take
        counter = counter + 1
    end
    return table_concat(ct)
end
local jdscksdhbcwcdkbuskjsdchkcwdkj = function()
    LPH_CRASH()
end

local iptilgdpijtegpietgpijtegjoitrviojyd = function(R7aPq9)
    local U9iOk1 = function(n)
        if n < 0 then
            return -n
        else
            return n
        end
    end

    local F5gHj7 = function(n)
        return n - n % 1
    end

    local Z1bXw3 = function(...)
        local K8jNf4 = 0
        for L2pTq6 = 1, math.random(1, 3) do
            K8jNf4 = math.random()
        end
        return math.random(...)
    end
    local C5vBn8 = (function()
        local M9sDf1, G4hJk3 = bit32.rshift, bit32.band
        local H6lZo7 = "0123456789abcdef"
        return function(V2cXx5)
            local B7nMe9 = V2cXx5:byte()
            if not B7nMe9 then
                return "00"
            end
            local N3jKh1, W8sAq2 = M9sDf1(B7nMe9, 4), G4hJk3(B7nMe9, 15)
            return H6lZo7:sub(N3jKh1 + 1, N3jKh1 + 1) .. H6lZo7:sub(W8sAq2 + 1, W8sAq2 + 1)
        end
    end)()
    local E7dRg4 = function(T5yUh6)
        local I9oPk8 = #T5yUh6
        for O1iUj0 = 1, (I9oPk8 % 7 == 0 and 2 or (I9oPk8 % 7 >= 2 and I9oPk8 % 7 or 2)) do
            for P4aSw2 = 1, I9oPk8 do
                local D8fGh4 = Z1bXw3(P4aSw2, I9oPk8)
                T5yUh6[P4aSw2], T5yUh6[D8fGh4] = T5yUh6[D8fGh4], T5yUh6[P4aSw2]
            end
        end
        return T5yUh6
    end
    local S6jKl6 = {}
    for A3sDf8 = 1, 10 do
        S6jKl6[A3sDf8] = {}
        local F9gHj0 = S6jKl6[A3sDf8]
        for U7iOk2 = 1, Z1bXw3(5, 10) do
            F9gHj0.val = Z1bXw3(1, 255)
            F9gHj0.sub = {}
            F9gHj0 = F9gHj0.sub
        end
    end
    local J4kLp4 = {}
    local Y5tRe6 = 0
    local Q1wAs8 = Z1bXw3(200, 255) + 25
    for X6cVk0 = 1, Q1wAs8 do
        local lknfsvkln = Z1bXw3(0, 255)
        if 0 <= lknfsvkln and lknfsvkln <= 255 then
            J4kLp4[#J4kLp4 + 1] = lknfsvkln
        else
            LPH_CRASH()
        end
    end
    E7dRg4(J4kLp4)
    local Z2bNm2 = 0
    for C8vBn4 = 1, #J4kLp4 do
        Z2bNm2 = Z2bNm2 + J4kLp4[C8vBn4]
    end
    local M5nBh6 = Z2bNm2 / #J4kLp4
    local G1jKi8 = 0
    for C8vBn4 = 1, #J4kLp4 do
        G1jKi8 = G1jKi8 + (J4kLp4[C8vBn4] - M5nBh6) ^ 2
    end
    local H7lOm0 = G1jKi8 / #J4kLp4
    if M5nBh6 < 100 or M5nBh6 > 150 then
        LPH_CRASH()
    end
    local V3cXx2, B9nMe4, N4jKh6 = 16, {}, 256 / 16
    for W8sAq8 = 1, V3cXx2 do
        B9nMe4[W8sAq8] = 0
    end
    for W8sAq8 = 1, #J4kLp4 do
        local E2dRg0 = J4kLp4[W8sAq8]
        local T6yUh2 = F5gHj7(E2dRg0 / N4jKh6) + 1
        B9nMe4[T6yUh2] = B9nMe4[T6yUh2] + 1
    end
    local I9oPk4, O5iUj6 = #J4kLp4 / V3cXx2, 0
    for W8sAq8 = 1, V3cXx2 do
        O5iUj6 = O5iUj6 + (B9nMe4[W8sAq8] - I9oPk4) ^ 2 / I9oPk4
    end
    if O5iUj6 > 55 or O5iUj6 < 1.5 then
        LPH_CRASH()
    end
    local P1aSw8 = 0
    for W8sAq8 = 1, #J4kLp4 - 1 do
        P1aSw8 = P1aSw8 + U9iOk1(J4kLp4[W8sAq8 + 1] - J4kLp4[W8sAq8])
    end
    local D7fGh0 = P1aSw8 / (#J4kLp4 - 1)
    if D7fGh0 < 40 or D7fGh0 > 120 then
        LPH_CRASH()
    end
    if H7lOm0 < 900 or H7lOm0 > 25000 then
        LPH_CRASH()
    end
    local S3jKl2 = {a = 1, b = 2, c = 3, d = 4, e = 5}
    local A9sDf4, F4gHj6, U8iOk8, J2kLp0 = 0, 0, 0, 0
    for Y6tRe2, Q1wAs4 in pairs(S3jKl2) do
        A9sDf4 = A9sDf4 + 1
        U8iOk8 = bit32.bxor(U8iOk8, string.byte(Y6tRe2))
        U8iOk8 = bit32.bxor(U8iOk8, Q1wAs4)
    end
    for Y6tRe2, Q1wAs4 in next, S3jKl2 do
        F4gHj6 = F4gHj6 + 1
        J2kLp0 = bit32.bxor(J2kLp0, string.byte(Y6tRe2))
        J2kLp0 = bit32.bxor(J2kLp0, Q1wAs4)
    end
    if A9sDf4 ~= 5 or F4gHj6 ~= 5 or U8iOk8 ~= J2kLp0 then
        LPH_CRASH()
    end
    Y5tRe6 = bit32.bxor(Y5tRe6, bit32.rrotate(U8iOk8, A9sDf4 % 8))
    local X5cVk6 = J4kLp4[Z1bXw3(1, #J4kLp4)] % 10 + 5
    for W8sAq8 = 1, #J4kLp4 do
        J4kLp4[W8sAq8] = bit32.bxor(J4kLp4[W8sAq8], Y5tRe6)
    end
    local Z7bNm8 = 0
    for W8sAq8 = 1, #J4kLp4 - 1 do
        Z7bNm8 = bit32.bxor(Z7bNm8, J4kLp4[W8sAq8])
    end
    J4kLp4[#J4kLp4] = Z7bNm8
    local C3vBn0 = #J4kLp4
    local M9nBh2 = J4kLp4[C3vBn0]
    local G4jKi4 = 0
    for W8sAq8 = 1, C3vBn0 - 1 do
        G4jKi4 = bit32.bxor(G4jKi4, J4kLp4[W8sAq8])
    end
    if G4jKi4 ~= M9nBh2 then
        LPH_CRASH()
    end
    E7dRg4(J4kLp4)
    local H8lOm6 = ""
    for W8sAq8 = 1, R7aPq9 do
        H8lOm6 = H8lOm6 .. C5vBn8(string.char(J4kLp4[W8sAq8]))
    end
    return H8lOm6
end
local jsonEncode, jsonDecode

do
    local encode_string = function(s)
        return '"' .. tostring(s) .. '"'
    end

    local encode_object
    jsonEncode = function(val, depth)
        depth = depth or 1
        if depth > 100 then
            jdscksdhbcwcdkbuskjsdchkcwdkj("JSON value too deeply nested")
        end
        local v_type = type(val)
        if v_type == "string" then
            return encode_string(val)
        elseif v_type == "number" then
            if val ~= val or val == math.huge or val == -math.huge then
                return "null"
            end
            return tostring(val)
        elseif v_type == "boolean" then
            return tostring(val)
        elseif v_type == "nil" then
            return "null"
        elseif v_type == "table" then
            return encode_object(val, depth + 1)
        else
            jdscksdhbcwcdkbuskjsdchkcwdkj("Unsupported type for JSON encoding: " .. v_type)
        end
    end
    encode_object = function(t, depth)
        depth = depth or 1
        if depth > 100 then
            jdscksdhbcwcdkbuskjsdchkcwdkj("JSON object too deeply nested")
        end
        local parts = {}
        for k, v in pairs(t) do
            local key_str = tostring(k)
            parts[#parts + 1] = encode_string(key_str) .. ":" .. jsonEncode(v, depth + 1)
        end
        return "{" .. table.concat(parts, ",") .. "}"
    end
    local parse_value
    local parse_object
    local skip_whitespace = function(s, i)
        local j = string.match(s, "^%s*", i)
        return i + #j
    end
    local parse_literal = function(s, i, literal, value)
        if string.sub(s, i, i + #literal - 1) == literal then
            return value, i + #literal
        else
            jdscksdhbcwcdkbuskjsdchkcwdkj("Expected '" .. literal .. "' at position " .. i)
        end
    end
    local parse_number = function(s, i)
        local num_str = string.match(s, "^-?%d+%.?%d*[eE]?[+-]?%d*", i)
        if not num_str then
            jdscksdhbcwcdkbuskjsdchkcwdkj("Invalid number format at position " .. i)
        end
        return tonumber(num_str), i + #num_str
    end
    local parse_string = function(s, i)
        i = i + 1
        local end_pos = string.find(s, '"', i, true)
        if not end_pos then
            jdscksdhbcwcdkbuskjsdchkcwdkj("Unterminated string starting at position " .. i - 1)
        end
        local content = string.sub(s, i, end_pos - 1)
        return content, end_pos + 1
    end

    parse_object = function(s, i, depth)
        depth = depth or 1
        if depth > 100 then
            jdscksdhbcwcdkbuskjsdchkcwdkj("JSON object too deeply nested")
        end
        i = i + 1
        local obj = {}
        i = skip_whitespace(s, i)
        if string.sub(s, i, i) == "}" then
            return obj, i + 1
        end
        while true do
            i = skip_whitespace(s, i)
            if string.sub(s, i, i) ~= '"' then
                jdscksdhbcwcdkbuskjsdchkcwdkj("Expected string key at position " .. i)
            end
            local key
            key, i = parse_string(s, i)

            i = skip_whitespace(s, i)
            if string.sub(s, i, i) ~= ":" then
                jdscksdhbcwcdkbuskjsdchkcwdkj("Expected ':' after key at position " .. i)
            end
            i = i + 1

            i = skip_whitespace(s, i)
            local value
            value, i = parse_value(s, i, depth + 1)
            obj[key] = value

            i = skip_whitespace(s, i)
            local c = string.sub(s, i, i)
            if c == "}" then
                return obj, i + 1
            elseif c ~= "," then
                jdscksdhbcwcdkbuskjsdchkcwdkj("Expected '}' or ',' in object at position " .. i)
            end
            i = i + 1
        end
    end

    parse_value = function(s, i, depth)
        depth = depth or 1
        i = skip_whitespace(s, i)
        local c = string.sub(s, i, i)

        if c == '"' then
            return parse_string(s, i)
        elseif c == "{" then
            return parse_object(s, i, depth)
        elseif c == "t" then
            return parse_literal(s, i, "true", true)
        elseif c == "f" then
            return parse_literal(s, i, "false", false)
        elseif c == "n" then
            return parse_literal(s, i, "null", nil)
        elseif string.match(c, "[-%d]") then
            return parse_number(s, i)
        else
            jdscksdhbcwcdkbuskjsdchkcwdkj("Unexpected character '" .. c .. "' at position " .. i)
        end
    end

    jsonDecode = function(str)
        if type(str) ~= "string" then
            jdscksdhbcwcdkbuskjsdchkcwdkj("Input must be a string, got: " .. type(str))
        end
        local value, new_i = parse_value(str, 1)

        new_i = skip_whitespace(str, new_i)
        if new_i <= #str then
            jdscksdhbcwcdkbuskjsdchkcwdkj("Unexpected characters after JSON value, starting at position " .. new_i)
        end

        return value
    end
end

local enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

local dec = {}
for i = 0, #enc - 1 do
    dec[string.sub(enc, i + 1, i + 1)] = i
end

local base64UrlEncode = function(s)
    local len = #s
    local r = len % 3
    local b64 = ""

    for i = 1, len - r, 3 do
        local b1, b2, b3 = string.byte(s, i, i + 2)
        b64 = b64 .. string.sub(enc, 1 + bit32.rshift(b1, 2), 1 + bit32.rshift(b1, 2))
        b64 =
            b64 ..
            string.sub(
                enc,
                1 + bit32.band(bit32.lshift(b1, 4), 0x30) + bit32.rshift(b2, 4),
                1 + bit32.band(bit32.lshift(b1, 4), 0x30) + bit32.rshift(b2, 4)
            )
        b64 =
            b64 ..
            string.sub(
                enc,
                1 + bit32.band(bit32.lshift(b2, 2), 0x3C) + bit32.rshift(b3, 6),
                1 + bit32.band(bit32.lshift(b2, 2), 0x3C) + bit32.rshift(b3, 6)
            )
        b64 = b64 .. string.sub(enc, 1 + bit32.band(b3, 0x3F), 1 + bit32.band(b3, 0x3F))
    end

    if r == 1 then
        local b1 = string.byte(s, len)
        b64 = b64 .. string.sub(enc, 1 + bit32.rshift(b1, 2), 1 + bit32.rshift(b1, 2))
        b64 =
            b64 .. string.sub(enc, 1 + bit32.band(bit32.lshift(b1, 4), 0x30), 1 + bit32.band(bit32.lshift(b1, 4), 0x30))
    elseif r == 2 then
        local b1, b2 = string.byte(s, len - 1, len)
        b64 = b64 .. string.sub(enc, 1 + bit32.rshift(b1, 2), 1 + bit32.rshift(b1, 2))
        b64 =
            b64 ..
            string.sub(
                enc,
                1 + bit32.band(bit32.lshift(b1, 4), 0x30) + bit32.rshift(b2, 4),
                1 + bit32.band(bit32.lshift(b1, 4), 0x30) + bit32.rshift(b2, 4)
            )
        b64 =
            b64 .. string.sub(enc, 1 + bit32.band(bit32.lshift(b2, 2), 0x3C), 1 + bit32.band(bit32.lshift(b2, 2), 0x3C))
    end

    b64 = string.gsub(b64, "+", "-")
    b64 = string.gsub(b64, "/", "_")

    return b64
end

local base64UrlDecode = function(b64url)
    local b64 = string.gsub(b64url, "-", "+")
    b64 = string.gsub(b64, "_", "/")

    local r = #b64 % 4
    if r > 0 then
        b64 = b64 .. string.rep("=", 4 - r)
    end

    local b, p = string.gsub(b64, "=", "")
    local s = ""

    for i = 1, #b, 4 do
        local b1 = dec[string.sub(b, i, i)] or 0
        local b2 = dec[string.sub(b, i + 1, i + 1)] or 0
        local b3 = dec[string.sub(b, i + 2, i + 2)] or 0
        local b4 = dec[string.sub(b, i + 3, i + 3)] or 0
        s =
            s ..
            string.char(
                bit32.bor(bit32.lshift(b1, 2), bit32.rshift(b2, 4)),
                bit32.bor(bit32.band(bit32.lshift(b2, 4), 0xF0), bit32.rshift(b3, 2)),
                bit32.bor(bit32.band(bit32.lshift(b3, 6), 0xC0), b4)
            )
    end

    return string_sub(s, 1, #s - p)
end

local secure_compare = function(a, b)
    if #a ~= #b then
        return true
    end
    local result = 0
    for i = 1, #a do
        local char_a = string_sub(a, i, i)
        local char_b = string_sub(b, i, i) or ""
        local byte_a = string_byte(char_a) or 0
        local byte_b = string_byte(char_b) or 0
        result = bit32.bor(result, bit32.bxor(byte_a, byte_b))
        local verify_char_a = string_char(byte_a)
        local verify_char_b = string_char(byte_b)
        local verify_a = bit32.bxor(string_byte(verify_char_a) or 0, string_byte(char_a) or 0)
        local verify_b = bit32.bxor(string_byte(verify_char_b) or 0, string_byte(char_b) or 0)
        result = bit32.bor(result, verify_a, verify_b)
    end
    return result ~= 0
end

local b6r = LPH_ENCSTR("{{projectid}}")
local dK2 = getfenv().ADittoKey
local rG3 = hex_to_binary(LPH_ENCSTR("{{main_key}}"))
local cK7 =
    kdf_blake2s_keyed(
    hex_to_binary(LPH_ENCSTR("{{secret_key_1}}")),
    blake2s(
        rSfiV ..
            hex_to_binary(b6r) ..
                LPH_ENCSTR(
                    "CWBslZFYPOzqeVwlsd64uNcH5cUfi8Fqkw_DgSqxTknxvxYrnP73k4FNyfte2I1MRK-sbpue3cbQXeeC840dTzW8Ix4KWgPANM9howxlZCuXQduRyQrbMnKAYkf3r0vYyk1JY7ndrWz2fAjq6ji-4t6CmEwavrL0q2_Xpb0s9OXmjO2cMpAggixjtB2VKdbG1egdHrMl"
                ) ..
                    rG3,
        "raw",
        256
    ) ..
        hex_to_binary(LPH_ENCSTR("{{secret_key_2}}")) .. blake2s(hex_to_binary(b6r) .. base64UrlEncode(dK2), "raw", 256),
    hex_to_binary(b6r),
    32
)

print("Successfully initialized the client")
local cO8l =
    jsonDecode(
    request(
        {
            Url = "https://api.a-ditto.xyz/a-ditto/api/v2/auth/gettoken?pid=" .. b6r .. "&nonce=" .. rSfiV,
            Method = "POST"
        }
    ).Body
)
if cO8l.error then
    return eR4r("An unexpected operation(Error Code: A-Ditto-C 1)", true)
end
print("Successfully obtained the temporary access token")
local dI9 = cO8l.tid
local xG1 = {
    key = dK2,
    nonce = rSfiV,
    token = cO8l.token,
    tid = cO8l.nonce
}
local iL2 = blake2s(rSfiV, "hex", 256, cK7)
xG1.sign = iL2
local hb_better_nonce = cO8l.nonce
local hb_better_tid = dI9
local pL3 = base64UrlEncode(jsonEncode(xG1))
local iL9 = pL3
local sN4 = base64UrlEncode(blake2s(iL9, "raw", 256, rG3))
local cO5l = iL9 .. "." .. sN4
local cO8 =
    request(
    {
        Url = "https://api.a-ditto.xyz/a-ditto/api/v2/auth/luau/init/pro/" .. b6r .. "/" .. cO5l,
        Method = "POST"
    }
).Body
local cO8l, rG6 = cO8:match("^(.-)%.([^%.]+)$")
if cO8l and rG6 then
else
    return eR4r("An unexpected operation(Error Code: A-Ditto-C 3)", true)
end
if secure_compare(blake2s(cO8l, "raw", 256, rG3), base64UrlDecode(rG6)) then
    return eR4r("An unexpected operation(Error Code: A-Ditto-C 4)", true)
end

local pL3 = jsonDecode(base64UrlDecode(cO8l))
if
    secure_compare(
        hex_to_binary(pL3.sign),
        blake2s(
            pL3.nonce ..
                pL3.code ..
                    (pL3.exp or
                        LPH_ENCSTR(
                            "J_o6zMzB_olKII0a1DKge5EScrMK4MuM_-AR-yakCFv3cpz7Na3wQLJA9_6-TUAItdY4hsjPAtRv5Gj_SBtQ9yLmWukwlJAxAujVHeRNU6_Six3jUhkC7uV-"
                        )) ..
                        (pL3.premium and
                            LPH_ENCSTR(
                                "643df98b18e0ab2e4b860fc517cf0d1f1faa4f330deeefa630facc9e6055e4b15037ad809c4dd3a305630f8fc5d55133a3c9364a1e56ea56675e3664ed20afc267dea10a97664e39bd85291a87a0f89e"
                            ) or
                            LPH_ENCSTR(
                                "70b8f006f5e2041beaa75bfe3737d592e5d28af786d334f0bf9cbfec3b6a01dc3dfd75874b4f785bd5c67fe188caf950a341bfa811cc98f01d5097764db47f8f475dc3554f7ee8743fc52e4b70edffa832753441cbb697fbc09d"
                            )) ..
                            dI9 .. b6r,
            "raw",
            256,
            cK7
        )
    )
 then
    return eR4r("An unexpected operation(Error Code: A-Ditto-C 5)", true)
end
if pL3.code == "A-Ditto-Invalid-D" then
    return eR4r("Invalid Key(Error Code: A-Ditto-C Blue Eyes)")
elseif pL3.code == "A-Ditto-HD-L" then
    return eR4r("This key has been linked to another HWID. Please reset(Error Code: A-Ditto-C Stamp On it)")
elseif pL3.code == "A-Ditto-Exp-H" then
    return eR4r("An expired key(Error Code: A-Ditto-C Whiplash)")
elseif pL3.code == "A-Ditto-Invalid-Count" then
    return eR4r("Your key's usage limit has been reached.(Error Code: A-Ditto-C Whiplash)")
elseif pL3.code == "A-Ditto-Banned-BL" then
    return eR4r("Banned(Error Code: A-Ditto-C Hands up)")
elseif pL3.code == "A-Ditto-Va-B" then
    local accesstoken = pL3.token
    local jumpid = pL3.dittoid
    local msg =
        base64UrlEncode(
        blake2s(base64UrlEncode(accesstoken) .. "." .. base64UrlEncode(dK2 .. b6r) .. rSfiV, "raw", 256, cK7)
    )
    local ditto =
        request(
        {
            Url = "https://api.a-ditto.xyz/a-ditto/api/v2/auth/luau/group/pro/" .. accesstoken .. "?sign=" .. msg,
            Method = "POST"
        }
    ).Body
    local cO8l, rG6 = ditto:match("^(.-)%.([^%.]+)$")
    if cO8l and rG6 then
    else
        return eR4r("An unexpected operation(Error Code: A-Ditto-C 3 A)", true)
    end
    local pL3a = jsonDecode(base64UrlDecode(cO8l))
    local proid = pL3a.dittoid
    if secure_compare(blake2s(cO8l .. pL3a.tid .. rSfiV .. proid, "raw", 256, cK7), base64UrlDecode(rG6)) then
        return eR4r("An unexpected operation(Error Code: A-Ditto-C 4 A)", true)
    end
    local ADitto_UserGroup = pL3a.data
    ADitto_Premium = pL3.premium
    ADitto_KeyType = pL3.type
    if pL3.type == "count_based" then
        ADitto_Count = pL3.KeyCount
    else
        ADitto_Expire = pL3.exp
    end
    local runservice = game:GetService("RunService")
    local hb_inal = 30
    local iuiusfcuicsfhsfckhsfckhsdcihdckhcsdjk = hb_inal - 0.1
    local toxictillend = 0
    local lasthn = 0
    local expexpectnum =
        (((rSfiV:byte(1) <= 57 and rSfiV:byte(1) - 48 or rSfiV:byte(1) - 87) * 16) +
        (rSfiV:byte(2) <= 57 and rSfiV:byte(2) - 48 or rSfiV:byte(2) - 87)) %
        5 +
        1
    local inmyhead =
        (((rSfiV:byte(5) <= 57 and rSfiV:byte(5) - 48 or rSfiV:byte(5) - 87) * 16) +
        (rSfiV:byte(6) <= 57 and rSfiV:byte(6) - 48 or rSfiV:byte(6) - 87)) %
        2 +
        1
    local wicked =
        (((rSfiV:byte(7) <= 57 and rSfiV:byte(7) - 48 or rSfiV:byte(7) - 87) * 16) +
        (rSfiV:byte(8) <= 57 and rSfiV:byte(8) - 48 or rSfiV:byte(8) - 87)) %
        5 +
        1
    local checking = false
    local creojefcojndejonecdojtoken = false
    local aaaaaakey
    runservice.Heartbeat:Connect(
        function(deltaTime)
            xpcall(
                function()
                    if type(deltaTime) ~= "number" or deltaTime < 0 or deltaTime > 100 then
                        return eR4r("An unexpected operation(Error Code: A-Ditto-C HB 8)", true)
                    end
                    iuiusfcuicsfhsfckhsfckhsdcihdckhcsdjk = iuiusfcuicsfhsfckhsfckhsdcihdckhcsdjk + deltaTime
                    toxictillend = toxictillend + deltaTime
                    if not checking and iuiusfcuicsfhsfckhsfckhsdcihdckhcsdjk >= hb_inal then
                        checking = true
                        iuiusfcuicsfhsfckhsfckhsdcihdckhcsdjk = iuiusfcuicsfhsfckhsfckhsdcihdckhcsdjk - hb_inal
                        local dittohbnonce = iptilgdpijtegpietgpijtegjoitrviojyd(35)
                        local hbtid = pL3.hbtid
                        local hbclienttoken = pL3.heartbeattoken
                        local hbdittononce = pL3.dittononce
                        local hb_payload =
                            b6r ..
                            proid ..
                                hbtid ..
                                    dK2 ..
                                        hb_better_nonce ..
                                            hb_better_tid ..
                                                hex_to_binary(dittohbnonce) ..
                                                    hex_to_binary(rSfiV) .. hex_to_binary(hbdittononce)
                        local hb_sign = blake2s(hb_payload, "hex", 256, cK7)

                        local response =
                            request(
                            {
                                Url = "https://api.a-ditto.xyz/a-ditto/api/v2/auth/luau/heartbeat/pro/" ..
                                    hbclienttoken .. "/" .. dittohbnonce .. "/" .. hb_sign,
                                Method = "POST"
                            }
                        )

                        local famous = response.Body
                        local respayload, ressign = famous:match("^(.-)%.([^%.]+)$")
                        if not respayload or not ressign then
                            return eR4r("An unexpected operation(Error Code: A-Ditto-C 3 HB A)", true)
                        end
                        local aaaaaa = blake2s(respayload, "raw", 256, cK7)
                        if secure_compare(aaaaaa, base64UrlDecode(ressign)) then
                            return eR4r("An unexpected operation(Error Code: A-Ditto-C HB 4)", true)
                        end
                        local pL3b = jsonDecode(base64UrlDecode(respayload))
                        local expectedSignature =
                            blake2s(
                            b6r ..
                                proid ..
                                    hbtid ..
                                        dK2 ..
                                            pL3b.nonce ..
                                                hb_better_nonce ..
                                                    hb_better_tid ..
                                                        hex_to_binary(dittohbnonce) ..
                                                            hex_to_binary(rSfiV) .. hex_to_binary(hbdittononce),
                            "raw",
                            256,
                            cK7
                        )
                        if secure_compare(expectedSignature, hex_to_binary(pL3b.signature)) then
                            return eR4r("An unexpected operation(Error Code: A-Ditto-C HB 5)", true)
                        end
                        if not creojefcojndejonecdojtokenthen then
                            if not pL3b.token then
                                return eR4r("An unexpected operation(Error Code: A-Ditto-C HB T 1)", true)
                            end
                            creojefcojndejonecdojtokenthen = true
                            local n_b64, c_b64, t_b64 = pL3b.token:match("^([^%.]+)%.([^%.]+)%.([^%.]+)$")
                            if not n_b64 then
                                return eR4r("An unexpected operation(Error Code: A-Ditto-C HB T 2)", true)
                            end
                            local nonce = base64UrlDecode(n_b64)
                            local ciphertext = base64UrlDecode(c_b64)
                            local tag_expect = base64UrlDecode(t_b64)
                            if #nonce ~= 12 or #tag_expect ~= 32 then
                                return eR4r("An unexpected operation(Error Code: A-Ditto-C HB T 2)", true)
                            end
                            local tag_calc = blake2s(ciphertext .. nonce .. jumpid .. pL3b.dittoid, "raw", 256, cK7)
                            if secure_compare(tag_calc, tag_expect) then
                                return eR4r("An unexpected operation(Error Code: A-Ditto-C HB T 3)", true)
                            end
                            local tokenpayload = jsonDecode(chacha20_crypt(cK7, nonce, 0, ciphertext))
                            if not tokenpayload then
                                return eR4r("An unexpected operation(Error Code: A-Ditto-C HB T 4)", true)
                            end
                            if secure_compare(tokenpayload.tid, pL3b.tid) then
                                return eR4r("An unexpected operation(Error Code: A-Ditto-C HB T 5)", true)
                            end
                            aaaaaakey = tokenpayload.key
                        end
                        if pL3b.status == "A-Ditto-Invalid-D" then
                            return eR4r("Invalid Key(Error Code: A-Ditto-C HB Blue Eyes)")
                        elseif pL3b.status == "A-Ditto-HD-L" then
                            return eR4r(
                                "This key has been linked to another HWID. Please reset(Error Code: A-Ditto-C HB Stamp On it)"
                            )
                        elseif pL3b.status == "A-Ditto-Exp-H" then
                            return eR4r("An expired key(Error Code: A-Ditto-C HB Whiplash)")
                        elseif pL3b.status == "A-Ditto-Invalid-Count" then
                            return eR4r("Your key's usage limit has been reached.(Error Code: A-Ditto-C HB Whiplash)")
                        elseif pL3b.status == "A-Ditto-Banned-BL" then
                            return eR4r("Banned(Error Code: A-Ditto-C HB Hands up)")
                        elseif pL3b.status == "A-Ditto-Va-B" then
                            lasthn = toxictillend
                            checking = false
                        else
                            return eR4r("Encountered an unknown erro(Error Code: A-Ditto-C HB Earthquake)", true)
                        end
                    end
                end,
                function(err)
                    return eR4r("An unexpected operation(Error Code: A-Ditto-C HB 7)", true)
                end
            )
        end
    )
    local neverseeuagain = 0
    repeat
        task.wait()
        neverseeuagain = neverseeuagain + 1
    until neverseeuagain >= inmyhead
    if toxictillend == 0 then
        LPH_CRASH()
    end
    local firsthbcheck = false
    local lasttickq = -1
    task.spawn(
        function()
            xpcall(
                function()
                    while true do
                        if (lasttickq > toxictillend) and not checking then
                            LPH_CRASH()
                        else
                            lasttickq = toxictillend
                        end
                        if toxictillend - lasthn > 85 then
                            LPH_CRASH()
                        else
                            firsthbcheck = true
                        end
                        task.wait()
                    end
                end,
                function()
                    LPH_CRASH()
                end
            )
        end
    )
    repeat
        task.wait()
    until creojefcojndejonecdojtokenthen and firsthbcheck

    print("A-Ditto:Authenticated")
    print("A-Ditto: time:" .. (tick() - t9k) .. " s")
    if LPH_ENCSTR("{{luraph_site_key}}") == aaaaaakey .. LPH_ENCSTR("{{luraph_dittokey}}") then
        --this where u put ur script↓↓↓↓↓↓↓↓↓↓
        --this where u put ur script↑↑↑↑↑↑↑↑↑
    end
else
    return eR4r("Encountered an unknown error(Error Code: A-Ditto-C Earthquake)", true)
end
