description = [[

Author: Paul JUNG/CIRCL - 2026
Licence:  GNU AFFERO GENERAL PUBLIC LICENSE

Checks for Ivanti EPPM MDM by requesting a known API endpoint.
Detection requires:
- HTTP 401 on known API endpoint
- Presence of Server header with value "server"
- Random page returning 404 (not 401)

https://help.ivanti.com/mi/help/en_us/CORE/12.x/api2/APIv2/IvantiEPMM_V2APIGuide.pdf
]]

categories = {"discovery"}

local http = require "http"
local shortport = require "shortport"

portrule = shortport.ssl

-- Generate a random string using only A–Z characters
local function generate_random_uppercase(length)
    local charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    local result = {}

    for index = 1, length do
        local random_index = math.random(1, #charset)
        result[index] = charset:sub(random_index, random_index)
    end

    return table.concat(result)
end

-- Example usage
local random_string = generate_random_uppercase(12)


action = function(host, port)
    local api_path = "/api/v2/appinventory/apps"

    local random_string = generate_random_uppercase(12)
    local random_path = "/" .. random_string

    -- First request: known Ivanti API endpoint
    local api_response = http.get(host, port, api_path, {
        ssl = true,
        timeout = 5000
    })

    if not api_response or api_response.status ~= 401 then
        return "Not Detected"
    end

    -- Verify Server header value
    local server_header = api_response.header["server"]
    if not server_header or server_header ~= "server" then
        return "Not Detected"
    end

    -- Second request: random page must return 404 (not 401)
    local random_response = http.get(host, port, random_path, {
        ssl = true,
        timeout = 5000
    })

    if not random_response or random_response.status ~= 404 then
        return "Not Detected"
    end

    return "PLUMTAG:Ivanti_EPPM"
end

