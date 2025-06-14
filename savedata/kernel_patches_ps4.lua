local shellcode_900 = ""

local shellcode_903 = ""

local shellcode_950 = ""

local shellcode_1000 = ""

local shellcode_1050 = ""

local shellcode_1100 = ""

local shellcode_1102 = ""

local shellcode_1150 = ""

local shellcode_1200 = ""

function get_kernel_patches_shellcode()
    local shellcode = ""
    if FW_VERSION == "9.00" then
        shellcode = shellcode_900
    elseif FW_VERSION == "9.03" or FW_VERSION == "9.04" then
        shellcode = shellcode_903
    elseif FW_VERSION == "9.50" or FW_VERSION == "9.51" or FW_VERSION == "9.60" then
        shellcode = shellcode_950
    elseif FW_VERSION == "10.00" or FW_VERSION == "10.01" then
        shellcode = shellcode_1000
    elseif FW_VERSION == "10.50" or FW_VERSION == "10.70" or FW_VERSION == "10.71" then
        shellcode = shellcode_1050
    elseif FW_VERSION == "11.00" then
        shellcode = shellcode_1100
    elseif FW_VERSION == "11.02" then
        shellcode = shellcode_1102
    elseif FW_VERSION == "11.50" or FW_VERSION == "11.52" then
        shellcode = shellcode_1150
    elseif FW_VERSION == "12.00" or FW_VERSION == "12.02" then
        shellcode = shellcode_1200
    end
    if #shellcode == 0 then
        return ""
    end
    
    local bin_data = hex_to_binary(shellcode)
    return bin_data
end
