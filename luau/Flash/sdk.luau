xpcall(
    function()
        local startTime = tick()
        print(
            [==[    
A-Ditto Auth SDK                                                    
__     __      ____  
\ \   / /      |___ \ 
 \ \ / /         __) |
  \ V /         / __/ 
   \_/         |_____|
   
 _____    _                    _     
|  ___|  | |    __ _    ___   | |__  
| |_     | |   / _` |  / __|  | '_ \ 
|  _|    | |  | (_| |  \__ \  | | | |
|_|      |_|   \__,_|  |___/  |_| |_|                                    
By continuing you agree to the
User Agreement: https://a-ditto.xyz/user-agreement
Privacy Policy: https://a-ditto.xyz/privacy-policy
Learn more at https://a-ditto.xyz/]==]
        )
        local kickPlayer = function(kickMessage)
            task.spawn(
                function()
                    local LocalPlayer = game.Players.LocalPlayer
                    LocalPlayer:Kick(kickMessage)
                end
            )
            task.wait(9)
            while true do
            end
        end
        if not getfenv().ADittoKey or #getfenv().ADittoKey <= 1 then
            return kickPlayer("Enter A Valid Key(Error Code: A-Ditto-C COOL)")
        end
        
        --some initialization checks and generate the nonce
        local getRandomValue = function(...)
            local randomNumber = 0
            for _ = 1, math.random(1, 3) do
                randomNumber = math.random()
            end
            return math.random(...)
        end
        local byteToHex = (function()
            local rshift, band = bit32.rshift, bit32.band
            local hexChars = "0123456789abcdef"
            return function(byteValue)
                local value = string.byte(byteValue)
                if not value then
                    return "00"
                end
                local high, low = rshift(value, 4), band(value, 15)
                return hexChars:sub(high + 1, high + 1) .. hexChars:sub(low + 1, low + 1)
            end
        end)()
        local shuffleTable = function(inputTable)
            local tableSize = #inputTable
            for i = 1, (tableSize % 7 == 0 and 2 or (tableSize % 7 >= 2 and tableSize % 7 or 2)) do
                for j = 1, tableSize do
                    local randomIndex = getRandomValue(j, tableSize)
                    inputTable[j], inputTable[randomIndex] = inputTable[randomIndex], inputTable[j]
                end
            end
            return inputTable
        end
        local nestedTables = {}
        for i = 1, 10 do
            nestedTables[i] = {}
            local currentTable = nestedTables[i]
            for _ = 1, getRandomValue(5, 10) do
                currentTable.val = getRandomValue(1, 255)
                currentTable.sub = {}
                currentTable = currentTable.sub
            end
        end
        local randomBytes = {}
        local xorValue = 0
        local arraySize = getRandomValue(200, 255) + 25
        for _ = 1, arraySize do
            local jfhckhdfjk = getRandomValue(0, 255)
            if 0<= jfhckhdfjk and jfhckhdfjk<=255 then
             randomBytes[#randomBytes + 1] = jfhckhdfjk
            else
             while true do end
            end
        end
        shuffleTable(randomBytes)
        local sum = 0
        for i = 1, #randomBytes do
            sum = sum + randomBytes[i]
        end
        local mean = sum / #randomBytes
        local varianceSum = 0
        for i = 1, #randomBytes do
            varianceSum = varianceSum + (randomBytes[i] - mean) ^ 2
        end
        local variance = varianceSum / #randomBytes
        if mean < 100 or mean > 150 then
            while true do
            end
        end
        local numBins, bins, binSize = 16, {}, 256 / 16
        for i = 1, numBins do
            bins[i] = 0
        end
        for i = 1, #randomBytes do
            local value = randomBytes[i]
            local binIndex = math.floor(value / binSize) + 1
            bins[binIndex] = bins[binIndex] + 1
        end
        local expectedFrequency, chiSquared = #randomBytes / numBins, 0
        for i = 1, numBins do
            chiSquared = chiSquared + (bins[i] - expectedFrequency) ^ 2 / expectedFrequency
        end
        if chiSquared > 55 or chiSquared < 1.5 then
            while true do
            end
        end
        local diffSum = 0
        for i = 1, #randomBytes - 1 do
            diffSum = diffSum + math.abs(randomBytes[i + 1] - randomBytes[i])
        end
        local averageDifference = diffSum / (#randomBytes - 1)
        if averageDifference < 40 or averageDifference > 120 then
            while true do
            end
        end
        if variance < 900 or variance > 25000 then
            while true do
            end
        end
        local sampleTable = {a = 1, b = 2, c = 3, d = 4, e = 5}
        local pairsCount, nextCount, pairsXor, nextXor = 0, 0, 0, 0
        for k, v in pairs(sampleTable) do
            pairsCount = pairsCount + 1
            pairsXor = bit32.bxor(pairsXor, string.byte(k))
            pairsXor = bit32.bxor(pairsXor, v)
        end
        for k, v in next, sampleTable do
            nextCount = nextCount + 1
            nextXor = bit32.bxor(nextXor, string.byte(k))
            nextXor = bit32.bxor(nextXor, v)
        end
        if pairsCount ~= 5 or nextCount ~= 5 or pairsXor ~= nextXor then
            while true do
            end
        end
        xorValue = bit32.bxor(xorValue, bit32.rrotate(pairsXor, pairsCount % 8))
        local randomLength = randomBytes[getRandomValue(1, #randomBytes)] % 10 + 5
        for _ = 1, randomLength do
            local success, result =
                pcall(
                function()
                    local table1, table2 = {v = getRandomValue(10, 20)}, {v = getRandomValue(1, 9)}
                    local metatableMethods = {
                        __add = function(obj1, obj2)
                            return obj1.v + obj2.v
                        end,
                        __len = function(obj)
                            return obj.v * 2
                        end
                    }
                    setmetatable(table1, metatableMethods)
                    if (table1 + table2) ~= (table1.v + table2.v) or #table1 ~= table1.v * 2 then
                        return false
                    end
                    return true
                end
            )
            if not success or not result then
                while true do
                end
            end
            local protectedTable = {}
            setmetatable(protectedTable, {__metatable = "LOCKED"})
            if pcall(setmetatable, protectedTable, {}) then
                while true do
                end
            end
        end
        for i = 1, #randomBytes do
            randomBytes[i] = bit32.bxor(randomBytes[i], xorValue)
        end
        local checksum = 0
        for i = 1, #randomBytes - 1 do
            checksum = bit32.bxor(checksum, randomBytes[i])
        end
        randomBytes[#randomBytes] = checksum
        local lastPosition = #randomBytes
        local lastValue = randomBytes[lastPosition]
        local calculatedChecksum = 0
        for i = 1, lastPosition - 1 do
            calculatedChecksum = bit32.bxor(calculatedChecksum, randomBytes[i])
        end
        if calculatedChecksum ~= lastValue then
            while true do
            end
        end
        shuffleTable(randomBytes)
        local finalHexString = ""
        for i = 1, #randomBytes do
            finalHexString = finalHexString .. byteToHex(string.char(randomBytes[i]))
        end
        local nonce = finalHexString:sub(1, 50)--generate the nonce
        local createTrapTable = function()
            local trapFunction = function()
                while true do
                end
            end
            local trapMetatable = {
                __index = trapFunction,
                __newindex = trapFunction,
                __add = trapFunction,
                __sub = trapFunction,
                __mul = trapFunction,
                __div = trapFunction,
                __mod = trapFunction,
                __pow = trapFunction,
                __unm = trapFunction,
                __len = trapFunction,
                __eq = trapFunction,
                __lt = trapFunction,
                __le = trapFunction,
                __tostring = trapFunction,
                __call = trapFunction,
                __pairs = trapFunction,
                __ipairs = trapFunction,
                __metatable = trapFunction
            }
            return setmetatable({}, trapMetatable)
        end
        pcall(
            function()
                for _ = 1, getRandomValue(5, 15) do
                    local randomIndex1, randomIndex2 = getRandomValue(1, #nestedTables), getRandomValue(1, 20)
                    if nestedTables[randomIndex1] then
                        nestedTables[randomIndex1][randomIndex2] = createTrapTable()
                    end
                end
            end
        )
        local generateFunctions = function()
            local functions = {}
            local statusValue = getRandomValue(100, 255)
            local magicValue = getRandomValue(256, 300)
            local templateFunctions = {
                function(self, n)
                    statusValue = bit32.bxor(statusValue, n)
                    if statusValue == magicValue then
                        while true do
                        end
                    end
                    return statusValue
                end,
                function(self, n)
                    if getRandomValue(2, 100) == 1 then
                        while true do
                        end
                    end
                    return self[getRandomValue(1, #self)](self, n - 1)
                end,
                function(self, n)
                    local depth, maxDepth = n, getRandomValue(5, 10)
                    local function recursiveCall(s, currentDepth)
                        if currentDepth > maxDepth then
                            return currentDepth
                        end
                        return recursiveCall(s, currentDepth + 1)
                    end
                    return recursiveCall(self, 0)
                end
            }
            for i = 1, getRandomValue(10, 20) do
                functions[i] = templateFunctions[getRandomValue(1, #templateFunctions)]
            end
            return functions
        end
        local generatedFunctions = generateFunctions()
        pcall(
            function()
                for _ = 1, getRandomValue(10, 20) do
                    generatedFunctions[getRandomValue(1, #generatedFunctions)](generatedFunctions, getRandomValue(5, 15))
                end
            end
        )
        local globalVar, expectedValue = nil, "..."
        for _ = 1, getRandomValue(11, 255) do
            local success, _ =
                pcall(
                function()
                    task.spawn(
                        function()
                            local a = 1
                            local b = print
                        end
                    )
                    b(a)
                end
            )
            if success then
                while true do
                end
            end
        end
        for _ = 1, getRandomValue(11, 255) do
            local success, _ =
                pcall(
                function()
                end
            )
            if success ~= true then
                while true do
                end
            end
        end
        if globalVar then
            while true do
            end
        end
        for _ = 1, getRandomValue(11, 255) do
            task.spawn(
                function()
                    wKdk = 1
                end
            )
        end
        for _ = 1, getRandomValue(11, 255) do
            task.spawn(
                function()
                    globalVar = expectedValue
                end
            )
            if globalVar and globalVar ~= expectedValue then
                while true do
                end
            end
        end

        local band = bit32.band
        local bor = bit32.bor
        local bxor = bit32.bxor
        local rol = function(val, disp)
            disp = disp % 32
            return bit32.bor(bit32.lshift(val, disp), bit32.rshift(val, 32 - disp))
        end
        local bytesToUint32 = function(b1, b2, b3, b4)
            return b1 * 0x1000000 + b2 * 0x10000 + b3 * 0x100 + b4
        end
        local uint32ToBytes = function(val)
            local b4 = val % 256
            val = (val - b4) / 256
            local b3 = val % 256
            val = (val - b3) / 256
            local b2 = val % 256
            local b1 = (val - b2) / 256
            return b1, b2, b3, b4
        end
        local F_func = function(x, y, z)
            return bxor(z, band(x, bxor(y, z)))
        end
        local G_func = function(x, y, z)
            return bor(band(x, bor(y, z)), band(y, z))
        end
        local str_byte = string.byte
        local str_char = string.char
        local str_rep = function(str, n)
            if n <= 0 then
                return ""
            end
            local result = ""
            for i = 1, n do
                result = result .. str
            end
            return result
        end
        local toHex = function(str)
            local resultTable = {}
            local hexChars = ("0123456789abcdef")
            for i = 1, #str do
                local byte = string.byte(str, i)
                local highNibble = bit32.rshift(byte, 4)
                local lowNibble = bit32.band(byte, 0x0F)
                resultTable[#resultTable + 1] = hexChars:sub(highNibble + 1, highNibble + 1)
                resultTable[#resultTable + 1] = hexChars:sub(lowNibble + 1, lowNibble + 1)
            end
            local hexString = ""
            for i = 1, #resultTable do
                hexString = hexString .. resultTable[i]
            end
            return hexString
        end

        local sha1 = function(message, mode)--SHA-1: a cryptographic hash algorithm
            local padding = str_char(0x80)
            local length_field_size = 8
            local padded_length = #message + 1 + length_field_size
            local padding_zeros = str_rep(str_char(0), -padded_length % 64)
            local total_length_bits = str_char(0, 0, 0, 0, uint32ToBytes(#message * 8))
            message = message .. padding .. padding_zeros .. total_length_bits
            assert(#message % 64 == 0)
            local h0 = 0x67452301
            local h1 = 0xEFCDAB89
            local h2 = 0x98BADCFE
            local h3 = 0x10325476
            local h4 = 0xC3D2E1F0
            local w = {}
            for chunk_start = 1, #message, 64 do
                local offset = chunk_start
                for i = 0, 15 do
                    w[i] = bytesToUint32(str_byte(message, offset, offset + 3))
                    offset = offset + 4
                end
                for i = 16, 79 do
                    w[i] = rol(bxor(w[i - 3], w[i - 8], w[i - 14], w[i - 16]), 1)
                end
                local a = h0
                local b = h1
                local c = h2
                local d = h3
                local e = h4
                for i = 0, 79 do
                    local f
                    local k
                    if i <= 19 then
                        f = F_func(b, c, d)
                        k = 0x5A827999
                    elseif i <= 39 then
                        f = bxor(b, c, d)
                        k = 0x6ED9EBA1
                    elseif i <= 59 then
                        f = G_func(b, c, d)
                        k = 0x8F1BBCDC
                    else
                        f = bxor(b, c, d)
                        k = 0xCA62C1D6
                    end
                    local temp = (rol(a, 5) + f + e + k + w[i]) % 4294967296
                    e = d
                    d = c
                    c = rol(b, 30)
                    b = a
                    a = temp
                end
                h0 = (h0 + a) % 4294967296
                h1 = (h1 + b) % 4294967296
                h2 = (h2 + c) % 4294967296
                h3 = (h3 + d) % 4294967296
                h4 = (h4 + e) % 4294967296
            end
            if mode == "hex" then
                return toHex(str_char(uint32ToBytes(h0)) .. str_char(uint32ToBytes(h1)) .. str_char(uint32ToBytes(h2)) .. str_char(uint32ToBytes(h3)) .. str_char(uint32ToBytes(h4)))
            end
            return str_char(uint32ToBytes(h0)) .. str_char(uint32ToBytes(h1)) .. str_char(uint32ToBytes(h2)) .. str_char(uint32ToBytes(h3)) .. str_char(uint32ToBytes(h4))
        end
        local hex_to_binary = function(hex_str)
            local raw =
                (hex_str:gsub(
                "..",
                function(hex)
                    return string.char(tonumber(hex, 16))
                end
            ))
            return raw
        end
        local secure_compare = function(a, b)--A secure comparison function for safely checking whether two strings are equal.
            if type(a) ~= "string" or type(b) ~= "string" then
                return true
            end
            local len_a = #a
            local len_b = #b
            local result = 0
            for i = 1, len_a do
                local byte_a = string.byte(a, i)
                local byte_b = string.byte(b, i) or 0
                result = bit32.bor(result, bit32.bxor(byte_a, byte_b))
            end
            result = bit32.bor(result, bit32.bxor(len_a, len_b))
            return result ~= 0
        end

        local xor_with_0x36 = function(c)
            return string.char(bit32.bxor(string.byte(c), 0x36))
        end
        local xor_with_0x5c = function(c)
            return string.char(bit32.bxor(string.byte(c), 0x5c))
        end

        local hmac = function(key, text, hex_output)--HMAC (Hash-based Message Authentication Code)
            if type(key) ~= "string" then
                while true do
                end
            end
            if type(text) ~= "string" then
                while true do
                end
            end

            if #key > 64 then
                key = sha1(key, "byte")
            end
            key = key .. string.rep("\0", 64 - #key)

            local o_key_pad = key:gsub(".", xor_with_0x5c)
            local i_key_pad = key:gsub(".", xor_with_0x36)

            local inner_hash = sha1(i_key_pad .. text, "byte")

            local final_mode = hex_output and "hex" or "byte"
            return sha1(o_key_pad .. inner_hash, final_mode)
        end

        local hkdf = function(ikm, salt, info, length)--HKDF (HMAC-based Key Derivation Function)
            local HASH_LEN = 20
            local BLOCK_LEN = 64

            salt = salt
            info = info
            if type(length) ~= "number" then
                while true do
                end
            end
            if length > 255 * HASH_LEN then
                while true do
                end
            end

            local prk = hmac(salt, ikm, false)

            local okm = ""
            local T = ""
            local num_blocks = math.ceil(length / HASH_LEN)

            for i = 1, num_blocks do
                local message = T .. info .. string.char(i)
                T = hmac(prk, message, false)
                okm = okm .. T
            end

            return okm
        end

        local jsonEncode, jsonDecode--Json library

        do
            local manual_concat = function(t, sep)
                sep = sep or ""
                local res = ""
                for i = 1, #t do
                    res = res .. t[i]
                    if i < #t then
                        res = res .. sep
                    end
                end
                return res
            end

            local escape_map = {
                ['"'] = '\\"',
                ["\\"] = "\\\\",
                ["\b"] = "\\b",
                ["\f"] = "\\f",
                ["\n"] = "\\n",
                ["\r"] = "\\r",
                ["\t"] = "\\t"
            }

            local is_array = function(t)
                if next(t) == nil then
                    return true
                end
                local count = 0
                for _ in pairs(t) do
                    count = count + 1
                end
                return #t == count
            end

            local encode_value, encode_string, encode_array, encode_object

            encode_string = function(s)
                return '"' .. s:gsub('["\\\b\f\n\r\t]', escape_map) .. '"'
            end

            encode_array = function(t)
                local parts = {}
                for i = 1, #t do
                    parts[i] = encode_value(t[i])
                end
                return "[" .. manual_concat(parts, ",") .. "]"
            end

            encode_object = function(t)
                local parts = {}
                for k, v in pairs(t) do
                    if type(k) ~= "string" then
                        error("JSON object keys must be strings. Got: " .. type(k))
                    end
                    parts[#parts + 1] = encode_string(k) .. ":" .. encode_value(v)
                end
                return "{" .. manual_concat(parts, ",") .. "}"
            end

            encode_value = function(v)
                local v_type = type(v)
                if v_type == "string" then
                    return encode_string(v)
                elseif v_type == "number" then
                    if v ~= v or v == math.huge or v == -math.huge then
                        return "null"
                    end
                    return tostring(v)
                elseif v_type == "boolean" then
                    return tostring(v)
                elseif v_type == "nil" then
                    return "null"
                elseif v_type == "table" then
                    if is_array(v) then
                        return encode_array(v)
                    else
                        return encode_object(v)
                    end
                else
                    error("Unsupported type for JSON encoding: " .. v_type)
                end
            end

            jsonEncode = function(val)
                return encode_value(val)
            end
        end

        do
            local manual_concat = function(t, sep)
                sep = sep or ""
                local res = ""
                for i = 1, #t do
                    res = res .. t[i]
                    if i < #t then
                        res = res .. sep
                    end
                end
                return res
            end

            local s, i, parse_error
            local parse_value, parse_literal, parse_number, parse_string, parse_array, parse_object
            local init, peek, consume, skip_whitespace

            init = function(str)
                s, i = str, 1
                parse_error = function(msg)
                    while true do end
                end
            end

            peek = function()
                return s:sub(i, i)
            end
            consume = function()
                i = i + 1
                return s:sub(i - 1, i - 1)
            end
            skip_whitespace = function()
                i = s:find("%S", i) or #s + 1
            end

            parse_literal = function(literal, value)
                if s:sub(i, i + #literal - 1) == literal then
                    i = i + #literal
                    return value
                else
                    parse_error("Expected '" .. literal .. "'")
                end
            end

            parse_number = function()
                local num_str = s:match("^-?%d+%.?%d*[eE]?[%+%d-]*", i)
                if not num_str then
                    parse_error("Invalid number format")
                end
                i = i + #num_str
                return tonumber(num_str)
            end

            parse_string = function()
                local band = bit32 and bit32.band or function(a, b)
                        local r, p = 0, 1
                        while a > 0 and b > 0 do
                            if a % 2 == 1 and b % 2 == 1 then
                                r = r + p
                            end
                            a, b, p = (a - a % 2) / 2, (b - b % 2) / 2, p * 2
                        end
                        return r
                    end
                local bor = bit32 and bit32.bor or function(a, b)
                        return a + b - band(a, b)
                    end
                local rshift = bit32 and bit32.rshift or function(a, n)
                        return math.floor(a / (2 ^ n))
                    end
                local escape_map = {b = "\b", f = "\f", n = "\n", r = "\r", t = "\t"}
                local utf8_char = function(code)
                    if code <= 0x7f then
                        return string.char(code)
                    elseif code <= 0x7ff then
                        return string.char(bor(0xc0, rshift(code, 6)), bor(0x80, band(code, 0x3f)))
                    elseif code <= 0xffff then
                        return string.char(
                            bor(0xe0, rshift(code, 12)),
                            bor(0x80, band(rshift(code, 6), 0x3f)),
                            bor(0x80, band(code, 0x3f))
                        )
                    else
                        return "?"
                    end
                end

                consume()
                local parts = {}
                local start = i
                while i <= #s do
                    local next_esc = s:find('["\\]', i)
                    if not next_esc then
                        parse_error("Unterminated string")
                    end
                    parts[#parts + 1] = s:sub(start, next_esc - 1)
                    if s:sub(next_esc, next_esc) == '"' then
                        i = next_esc + 1
                        return manual_concat(parts)
                    else
                        i = next_esc + 1
                        local esc = consume()
                        if esc == "u" then
                            local hex = s:sub(i, i + 3)
                            if not hex:match("^[0-9a-fA-F]{4}$") then
                                parse_error("Invalid unicode escape")
                            end
                            parts[#parts + 1] = utf8_char(tonumber(hex, 16))
                            i = i + 4
                        else
                            parts[#parts + 1] = escape_map[esc] or esc
                        end
                        start = i
                    end
                end
                parse_error("Unterminated string")
            end

            parse_array = function()
                consume()
                local arr = {}
                skip_whitespace()
                if peek() == "]" then
                    consume()
                    return arr
                end
                while true do
                    arr[#arr + 1] = parse_value()
                    skip_whitespace()
                    if peek() == "]" then
                        consume()
                        return arr
                    end
                    if consume() ~= "," then
                        parse_error("Expected ']' or ',' in array")
                    end
                    skip_whitespace()
                end
            end

            parse_object = function()
                consume()
                local obj = {}
                skip_whitespace()
                if peek() == "}" then
                    consume()
                    return obj
                end
                while true do
                    if peek() ~= '"' then
                        parse_error("Expected string key")
                    end
                    local key = parse_string()
                    skip_whitespace()
                    if consume() ~= ":" then
                        parse_error("Expected ':' after key")
                    end
                    skip_whitespace()
                    obj[key] = parse_value()
                    skip_whitespace()
                    if peek() == "}" then
                        consume()
                        return obj
                    end
                    if consume() ~= "," then
                        parse_error("Expected '}' or ',' in object")
                    end
                    skip_whitespace()
                end
            end

            parse_value = function()
                skip_whitespace()
                local char = peek()
                if char == '"' then
                    return parse_string()
                elseif char == "{" then
                    return parse_object()
                elseif char == "[" then
                    return parse_array()
                elseif char == "t" then
                    return parse_literal("true", true)
                elseif char == "f" then
                    return parse_literal("false", false)
                elseif char == "n" then
                    return parse_literal("null", nil)
                elseif char == "-" or char:match("%d") then
                    return parse_number()
                else
                    parse_error("Invalid character '" .. (char or "EOF") .. "'")
                end
            end

            jsonDecode = function(json_string)
                if type(json_string) ~= "string" then
                    error("Input must be a string. Got: " .. type(json_string))
                end
                init(json_string)
                local result = parse_value()
                skip_whitespace()
                if i <= #s then
                    parse_error("Unexpected characters after JSON data")
                end
                return result
            end
        end

        local base64UrlEncode, base64UrlDecode--Base64url Library

        do
            local manual_concat = function(t, sep)
                sep = sep or ""
                local res = ""
                for i = 1, #t do
                    res = res .. t[i]
                    if i < #t then
                        res = res .. sep
                    end
                end
                return res
            end

            local lshift = bit32 and bit32.lshift or function(a, n)
                    return a * (2 ^ n)
                end
            local rshift = bit32 and bit32.rshift or function(a, n)
                    return math.floor(a / (2 ^ n))
                end
            local band = bit32 and bit32.band or function(a, b)
                    local r, p = 0, 1
                    while a > 0 and b > 0 do
                        if a % 2 == 1 and b % 2 == 1 then
                            r = r + p
                        end
                        a, b, p = (a - a % 2) / 2, (b - b % 2) / 2, p * 2
                    end
                    return r
                end
            local bor = bit32 and bit32.bor or function(a, b)
                    return a + b - band(a, b)
                end
            local B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            local B64_DECODE = {}
            for i = 1, #B64_CHARS do
                B64_DECODE[B64_CHARS:sub(i, i)] = i - 1
            end

            base64UrlEncode = function(data)
                local parts = {}
                local len = #data
                for i = 1, len, 3 do
                    local b1, b2, b3 = data:byte(i, i + 2)
                    local n1 = rshift(b1, 2)
                    local n2 = bor(lshift(band(b1, 3), 4), rshift(b2 or 0, 4))

                    parts[#parts + 1] = B64_CHARS:sub(n1 + 1, n1 + 1)
                    parts[#parts + 1] = B64_CHARS:sub(n2 + 1, n2 + 1)

                    if not b2 then
                        parts[#parts + 1] = "=="
                    else
                        local n3 = bor(lshift(band(b2, 15), 2), rshift(b3 or 0, 6))
                        parts[#parts + 1] = B64_CHARS:sub(n3 + 1, n3 + 1)
                        if not b3 then
                            parts[#parts + 1] = "="
                        else
                            local n4 = band(b3, 63)
                            parts[#parts + 1] = B64_CHARS:sub(n4 + 1, n4 + 1)
                        end
                    end
                end

                local b64_standard = manual_concat(parts)
                b64_standard = b64_standard:gsub("+", "-"):gsub("/", "_"):gsub("=", "")
                return b64_standard
            end

            base64UrlDecode = function(data)
                data = data:gsub("-", "+"):gsub("_", "/")
                local padding = #data % 4
                if padding > 0 then
                    data = data .. string.rep("=", 4 - padding)
                end

                local parts = {}
                for i = 1, #data, 4 do
                    local c1, c2, c3, c4 = data:sub(i, i + 3):match("(.)(.)(.)(.)")
                    local v1 = B64_DECODE[c1]
                    if not v1 then
                        error("Invalid Base64 character: '" .. c1 .. "'")
                    end
                    local v2 = B64_DECODE[c2]
                    if not v2 then
                        error("Invalid Base64 character: '" .. c2 .. "'")
                    end

                    parts[#parts + 1] = string.char(bor(lshift(v1, 2), rshift(v2, 4)))

                    if c3 ~= "=" then
                        local v3 = B64_DECODE[c3]
                        if not v3 then
                            error("Invalid Base64 character: '" .. c3 .. "'")
                        end
                        parts[#parts + 1] = string.char(bor(lshift(band(v2, 15), 4), rshift(v3, 2)))

                        if c4 ~= "=" then
                            local v4 = B64_DECODE[c4]
                            if not v4 then
                                error("Invalid Base64 character: '" .. c4 .. "'")
                            end
                            parts[#parts + 1] = string.char(bor(lshift(band(v3, 3), 6), v4))
                        end
                    end
                end
                return manual_concat(parts)
            end
        end
        local projectId = "{{projectid}}"
        local dittoKey = getfenv().ADittoKey--The key (or license) provided by the user
        local mainKey = hex_to_binary("{{main_key}}")
        local clientKey =
            hkdf(
            hex_to_binary("{{secret_key_1}}"),
            sha1(nonce .. hex_to_binary(projectId) .. "ditto" .. mainKey, "byte") .. hex_to_binary("{{secret_key_2}}"),
            hex_to_binary(projectId),
            20
        )--Use HDKF as the algorithm to derive a new key from the nonce generated by the client and your three keys
        print("Successfully initialized the client")
        local tokenResponse =
            jsonDecode(
            request(
                {
                    Url = "https://api.a-ditto.xyz/a-ditto/api/v2/auth/gettoken?pid=" .. projectId .. "&nonce=" .. nonce,
                    Method = "POST"
                }
            ).Body
        )--Request the server to obtain a temporary access token and any additional data
        if tokenResponse.error then
            return kickPlayer("An unexpected operation(Error Code: A-Ditto-C 1)", true)
        end
        print("Successfully obtained the temporary access token")
        local tokenid = tokenResponse.tid--the accesstoken's id
        local requestData = {
            key = dittoKey,
            nonce = nonce,
            token = tokenResponse.token,
            tid = tokenResponse.nonce
        }
        local signature = hmac(clientKey, nonce, "hex")
        requestData.sign = signature
        local payload = base64UrlEncode(jsonEncode(requestData))
        local signedPayload = payload
        local finalSignature = base64UrlEncode(hmac(mainKey, signedPayload, false))
        local inittoken = signedPayload .. "." .. finalSignature--A JWT with its header stripped off
        local initResponse =
            request(
            {
                Url = "https://api.a-ditto.xyz/a-ditto/api/v2/auth/luau/init/flash/" .. projectId .. "/" .. inittoken,
                Method = "POST"
            }
        ).Body
        local responsePayload, responseSignature = initResponse:match("^(.-)%.([^%.]+)$")
        if responsePayload and responseSignature then--Validate the token's format
        else
            return kickPlayer("An unexpected operation(Error Code: A-Ditto-C 3)", true)
        end
        if secure_compare(hmac(mainKey, responsePayload, false), base64UrlDecode(responseSignature)) then--Verify the JWT signature
            return kickPlayer("An unexpected operation(Error Code: A-Ditto-C 4)", true)
        end
        local decodedPayload = jsonDecode(base64UrlDecode(responsePayload))
        if
            secure_compare(
                hex_to_binary(decodedPayload.sign),
                hmac(clientKey, decodedPayload.nonce .. decodedPayload.code .. decodedPayload.exp .. (decodedPayload.premium and "ditto" or "cool") .. tokenid .. projectId, false)
            )--Use the key we just derived to verify the inner signature
         then
            return kickPlayer("An unexpected operation(Error Code: A-Ditto-C 5)", true)
        end
--check the status code
        if decodedPayload.code == "A-Ditto-Invalid-D" then
            return kickPlayer("Invalid Key(Error Code: A-Ditto-C Blue Eyes)")
        elseif decodedPayload.code == "A-Ditto-HD-L" then
            return kickPlayer("This key has been linked to another HWID. Please reset(Error Code: A-Ditto-C Stamp On it)")
        elseif decodedPayload.code == "A-Ditto-Exp-H" then
            return kickPlayer("An expired key(Error Code: A-Ditto-C Whiplash)")
        elseif decodedPayload.code == "A-Ditto-Invalid-Count" then
            return kickPlayer("Your key's usage limit has been reached.(Error Code: A-Ditto-C Whiplash)")
        elseif decodedPayload.code == "A-Ditto-Banned-BL" then
            return kickPlayer("Banned(Error Code: A-Ditto-C Hands up)")
        elseif decodedPayload.code == "A-Ditto-Va-B" then
            print("A-Ditto:Authenticated")
            print("A-Ditto: time:" .. (tick() - startTime) .. " s")
            local accesstoken = decodedPayload.token
            local msg = base64UrlEncode(hmac(clientKey, base64UrlEncode(accesstoken) .. "." .. base64UrlEncode(dittoKey .. projectId) .. nonce, false))--Generate the message's signature using HMAC
            local ditto =
                request(
                {
                    Url = "https://api.a-ditto.xyz/a-ditto/api/v2/auth/luau/group/flash/" ..
                        accesstoken .. "?sign=" .. msg,
                    Method = "POST"
                }
            ).Body--Use the access token we just obtained to request the group data
            local responsePayload, responseSignature = ditto:match("^(.-)%.([^%.]+)$")
            if responsePayload and responseSignature then
            else
                return kickPlayer("An unexpected operation(Error Code: A-Ditto-C 3 A)", true)
            end
            local groupPayload = jsonDecode(base64UrlDecode(responsePayload))
            if secure_compare(hmac(clientKey, responsePayload .. groupPayload.authid .. nonce, false), base64UrlDecode(responseSignature)) then--Generate the message's signature using HMAC
                return kickPlayer("An unexpected operation(Error Code: A-Ditto-C 4 A)", true)
            end
            ADitto_UserGroup = groupPayload.data
            ADitto_Premium = decodedPayload.premium
            ADitto_KeyType = decodedPayload.type
            if decodedPayload.type == "count_based" then
                ADitto_Count = decodedPayload.KeyCount
            else
                ADitto_Expire = decodedPayload.exp
            end
            pcall(
                function()
                    --this where u put ur script↓↓↓↓↓↓↓↓↓↓
                        
                    --this where u put ur script↑↑↑↑↑↑↑↑↑
                end
            )
        else
            return kickPlayer("Encountered an unknown error(Error Code: A-Ditto-C Earthquake)", true)
        end
    end,
    function()
        local kickPlayer = function(kickMessage)
            task.spawn(
                function()
                    local LocalPlayer = game.Players.LocalPlayer
                    LocalPlayer:Kick(kickMessage)
                end
            )
            task.wait(9)
            while true do
            end
        end
        return kickPlayer("Encountered an unknown error(Error Code: A-Ditto-C NMIXX)")
    end
)
