local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local url = require "url"
local base64 = require "base64"

description = [[
Gets the favicon from a web page then hash it using sha256 and the method
"http.favicon.hash" used by shodan.io murmur3_32(base64(favicon))
The results is displayed as a signed integer.

If the script argument <code>favicon.uri</code> is given, that relative URI is
always used to find the favicon. Otherwise, first the page at the root of the
web server is retrieved and parsed for a <code><link rel="icon"></code>
element. If that fails, the icon is looked for in <code>/favicon.ico</code>. If
a <code><link></code> favicon points to a different host or port, it is ignored.
]]

---
-- @args favicon.uri URI that will be requested for favicon.
-- @args favicon.root Web server path to search for favicon.
--
-- @usage
-- nmap --script=http-favicon.nse \
--    --script-args favicon.root=<root>,favicon.uri=<uri>
-- @output
-- |_ http-mmfavicon: signed integer

-- HTTP default favicon murmur32 (shodan like) / sha256 hash
-- rev 1.0 (2025-10-10)
-- Original NASL script by Javier Fernandez-Sanguino Pena
-- NSE http-favicon.nse by Vlatko Kosturjak
-- SHA256 Implementation by OGabrieLima https://github.com/OGabrieLima (2024-04-08) 

author = "CIRCL 2025 - Paul Jung (Thanat0s)"
license = ""
categories = {"default", "discovery", "safe"}
portrule = shortport.http

--[[
For thoses who wonder, in NMAP v7.94, LUA NSE is bundled with the following Openssl module:
 -      bignum_dec2bn
 -      bignum_pseudo_rand
 -      supported_ciphers
 -      supported_digests
 -      ripemd160
 -      DES_string_to_key
 -      bignum_num_bytes
 -      bignum_bn2hex
 -      decrypt
 -      bignum_bn2mpi
 -      bignum_mod_exp
 -      bignum_set_bit
 -      bignum_rand
 -      encrypt
 -      hmac
 -      digest
 -      bignum_div
 -      bignum_bn2dec
 -      bignum_bin2bn
 -      bignum_clear_bit
 -      md5
 -      bignum_bn2bin
 -      bignum_num_bits
 -      md4
 -      rand_pseudo_bytes
 -      bignum_is_safe_prime
 -      bignum_add
 -      rand_bytes
 -      bignum_hex2bn
 -      sha1
 -      bignum_is_bit_set
 -      bignum_is_prime
]]--

-- Auxiliary function: right rotation (bitwise)
local function bit_ror(x, y)
  return ((x >> y) | (x << (32 - y))) & 0xFFFFFFFF
end

-- helpers since lib int seems not available in nmap
local function toUint32(x) return x % 0x100000000 end
local function toInt32(x)
    x = x % 0x100000000
    if x >= 0x80000000 then x = x - 0x100000000 end
    return x
end
local function rshift(x,n) return math.floor(toUint32(x) / 2^n) end
local function lshift(x,n) return toUint32(toUint32(x) * 2^n) end
local function rol(x,n) return toUint32(lshift(x,n) + rshift(x,32-n)) end
local function bxor(a,b)
    local r, bitval = 0,1
    for i=1,32 do
        if (a % 2 + b % 2) % 2 == 1 then r = r + bitval end
        a = math.floor(a/2); b = math.floor(b/2); bitval = bitval * 2
    end
    return toUint32(r)
end
local function imul32(a,b)
    local a_lo, a_hi = a % 0x10000, math.floor(a / 0x10000)
    local b_lo, b_hi = b % 0x10000, math.floor(b / 0x10000)
    local low = a_lo * b_lo
    local mid = a_lo * b_hi + a_hi * b_lo
    return toUint32(low + mid * 0x10000)
end

-- Main function: MurmurHash3 32-bits
local function murmur3_32(data, seed)
    local h1 = seed or 0
    local c1, c2 = 0xcc9e2d51, 0x1b873593
    local len = #data
    local nblocks = math.floor(len/4)

    -- body
    for i=0,nblocks-1 do
        local j = i*4 + 1
        local k1 = data:byte(j) + lshift(data:byte(j+1),8) + lshift(data:byte(j+2),16) + lshift(data:byte(j+3),24)
        k1 = imul32(k1, c1)
        k1 = rol(k1,15)
        k1 = imul32(k1, c2)
        h1 = bxor(h1, k1)
        h1 = rol(h1,13)
        h1 = toUint32(imul32(h1,5) + 0xe6546b64)
    end

    -- tail
    local tail_index = nblocks*4 + 1
    local k1 = 0
    local rem = len % 4
    if rem == 3 then k1 = lshift(data:byte(tail_index+2),16) end
    if rem >= 2 then k1 = bxor(k1, lshift(data:byte(tail_index+1),8)) end
    if rem >= 1 then
        k1 = bxor(k1, data:byte(tail_index))
        k1 = imul32(k1, c1)
        k1 = rol(k1,15)
        k1 = imul32(k1, c2)
        h1 = bxor(h1,k1)
    end

    -- finalization
    h1 = bxor(h1, len)
    h1 = bxor(h1, rshift(h1,16))
    h1 = imul32(h1,0x85ebca6b)
    h1 = bxor(h1,rshift(h1,13))
    h1 = imul32(h1,0xc2b2ae35)
    h1 = bxor(h1,rshift(h1,16))

    return toInt32(h1)
end

-- Main function: SHA256
sha256 = function(message)
  local k = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  }

  local function preprocess(message)
      local len = #message
      local bitLen = len * 8
      message = message .. "\128" -- append single '1' bit

      local zeroPad = 64 - ((len + 9) % 64)
      if zeroPad ~= 64 then
          message = message .. string.rep("\0", zeroPad)
      end

      -- append length
      message = message .. string.char(
          bitLen >> 56 & 0xFF,
          bitLen >> 48 & 0xFF,
          bitLen >> 40 & 0xFF,
          bitLen >> 32 & 0xFF,
          bitLen >> 24 & 0xFF,
          bitLen >> 16 & 0xFF,
          bitLen >> 8 & 0xFF,
          bitLen & 0xFF
      )

      return message
  end

  local function chunkify(message)
      local chunks = {}
      for i = 1, #message, 64 do
          table.insert(chunks, message:sub(i, i + 63))
      end
      return chunks
  end

  local function processChunk(chunk, hash)
      local w = {}

      for i = 1, 64 do
          if i <= 16 then
              w[i] = string.byte(chunk, (i - 1) * 4 + 1) << 24 |
                     string.byte(chunk, (i - 1) * 4 + 2) << 16 |
                     string.byte(chunk, (i - 1) * 4 + 3) << 8 |
                     string.byte(chunk, (i - 1) * 4 + 4)
          else
              local s0 = bit_ror(w[i - 15], 7) ~ bit_ror(w[i - 15], 18) ~ (w[i - 15] >> 3)
              local s1 = bit_ror(w[i - 2], 17) ~ bit_ror(w[i - 2], 19) ~ (w[i - 2] >> 10)
              w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF
          end
      end

      local a, b, c, d, e, f, g, h = table.unpack(hash)

      for i = 1, 64 do
          local s1 = bit_ror(e, 6) ~ bit_ror(e, 11) ~ bit_ror(e, 25)
          local ch = (e & f) ~ ((~e) & g)
          local temp1 = (h + s1 + ch + k[i] + w[i]) & 0xFFFFFFFF
          local s0 = bit_ror(a, 2) ~ bit_ror(a, 13) ~ bit_ror(a, 22)
          local maj = (a & b) ~ (a & c) ~ (b & c)
          local temp2 = (s0 + maj) & 0xFFFFFFFF

          h = g
          g = f
          f = e
          e = (d + temp1) & 0xFFFFFFFF
          d = c
          c = b
          b = a
          a = (temp1 + temp2) & 0xFFFFFFFF
      end

      return (hash[1] + a) & 0xFFFFFFFF,
             (hash[2] + b) & 0xFFFFFFFF,
             (hash[3] + c) & 0xFFFFFFFF,
             (hash[4] + d) & 0xFFFFFFFF,
             (hash[5] + e) & 0xFFFFFFFF,
             (hash[6] + f) & 0xFFFFFFFF,
             (hash[7] + g) & 0xFFFFFFFF,
             (hash[8] + h) & 0xFFFFFFFF
  end

  message = preprocess(message)
  local chunks = chunkify(message)

  local hash = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
  for _, chunk in ipairs(chunks) do
      hash = {processChunk(chunk, hash)}
  end

  local result = ""
  for _, h in ipairs(hash) do
      result = result .. string.format("%08x", h)
  end

  return result
end

local function add_crlf(str, width)
    width = width or 76
    local t = {}
    for i = 1, #str, width do
        table.insert(t, str:sub(i, i + width - 1))
    end
    local s = table.concat(t, "\n")
    return s .. "\n"
end

action = function(host, port)
  local md5sum,answer
  local match
  local status, favicondb
  local results = stdnse.output_table()
   -- local results = {}
  local index, icon
  local root = ""

  if(stdnse.get_script_args('favicon.root')) then
    root = stdnse.get_script_args('favicon.root')
  end

  -- If parameter favicon.uri is given, we fetch it, always and only this.
  local favicon_uri = stdnse.get_script_args("favicon.uri")
  if(favicon_uri) then
    answer = http.get( host, port, root .. "/" .. favicon_uri)
    stdnse.debug4("Using URI %s", favicon_uri)
  else
    -- Otherwise, first try parsing the home page "/" for favicon reference.
    index = http.get( host, port, root .. "/" )
    if index.status == 200 or index.status == 503 then
      -- find the favicon pattern
      icon = parseIcon( index.body )
      -- if we find a pattern, we fetch it.
      if icon then
        local hostname = host.targetname or (host.name ~= "" and host.name) or host.ip
        stdnse.debug1("Got icon URL %s.", icon)
        local icon_host, icon_port, icon_path = parse_url_relative(icon, hostname, port.number, root)
        if (icon_host == host.ip or
          icon_host == host.targetname or
          icon_host == (host.name ~= '' and host.name)) and
          icon_port == port.number then
          -- request the favicon
          answer = http.get( icon_host, icon_port, icon_path )
        else
          answer = nil
        end
      else
        answer = nil
      end
    end

    -- If that didn't work, try /favicon.ico.
    if not answer or answer.status ~= 200 then
      answer = http.get( host, port, root .. "/favicon.ico" )
      stdnse.debug4("Using default URI.")
    end
  end

-- Finaly if we have a favicon, we hash it.
if answer and answer.status == 200 then
    stdnse.debug1("Favicon found.")
    local debugs = ""
    -- MurmurHash3 32 bits should be done on a B64 CLRF enabled dump.
    local rb64 = add_crlf(base64.enc(answer.body)) 
    results.faviconhash = murmur3_32(rb64)
    local sha256sum=sha256(answer.body)
    results.sha256 = sha256sum
    
    if nmap.verbosity() > 1  then
        local hex_debug = {}
        for i = 1, 128 do  
            hex_debug[#hex_debug+1] = string.format("%02X", rb64:byte(i))
        end
        -- In debug mode, shows the first bytes of favicon file.
        local hex_string = table.concat(hex_debug, "")
        results.debug = sha256sum .. " " .. "->" .. hex_string .. "<-"
    end
else
    stdnse.debug1("No favicon found.")
    return
end
return results
end

local function dirname(path)
  local dir
  dir = string.match(path, "^(.*)/")
  return dir or ""
end

-- Return a URL's host, port, and path, filling in the results with the given
-- host, port, and path if the URL is relative. Return nil if the scheme is not
-- "http" or "https".
function parse_url_relative(u, host, port, path)
  local scheme, abspath
  u = url.parse(u)
  scheme = u.scheme or "http"
  if not (scheme == "http" or scheme == "https") then
    return nil
  end
  abspath = u.path or ""
  if not string.find(abspath, "^/") then
    abspath = dirname(path) .. "/" .. abspath
  end
  return u.host or host, u.port or url.get_default_port(scheme), abspath
end

function parseIcon( body )
  local _, i, j
  local rel, href, word

  -- Loop through link elements.
  i = 0
  while i do
    _, i = string.find(body, "<%s*[Ll][Ii][Nn][Kk]%s", i + 1)
    if not i then
      return nil
    end
    -- Loop through attributes.
    j = i
    while true do
      local name, quote, value
      _, j, name, quote, value = string.find(body, "^%s*(%w+)%s*=%s*([\"'])(.-)%2", j + 1)
      if not j then
        break
      end
      if string.lower(name) == "rel" then
        rel = value
      elseif string.lower(name) == "href" then
        href = value
      end
    end
    for word in string.gmatch(rel or "", "%S+") do
      if string.lower(word) == "icon" then
        return href
      end
    end
  end
end
