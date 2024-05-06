local function printRed(text, location)
    print("^3" .. text:gsub(location, "^8" .. location)) -- ^3 light yellow, ^8 blood red
end

local function InitCipherScanner()
    print("^0Starting scan of resources")

    local foundSignature = false

    local signatures = {
        "\\x68\\x65\\x6c\\x70\\x43\\x6f\\x64\\x65",
        "\\x61\\x73\\x73\\x65\\x72\\x74",
        "\\x52\\x65\\x67\\x69\\x73\\x74\\x65\\x72\\x4e\\x65\\x74\\x45\\x76\\x65\\x6e\\x74",
        "\\x50\\x65\\x72\\x66\\x6F\\x72\\x6d\\x48\\x74\\x74\\x70\\x52\\x65\\x71\\x75\\x65\\x73\\x74",
        -- add more sigs
    }
    
    local currentRes = GetCurrentResourceName()

    local function GetResources()
        local resourceList = {}
        for i = 0, GetNumResources(), 1 do
            local resource_name = GetResourceByFindIndex(i)
            if resource_name and GetResourceState(resource_name) == "started" and resource_name ~= "_cfx_internal" and resource_name ~= currentRes then
                table.insert(resourceList, resource_name)
            end
        end
        return resourceList
    end
    
    local function FileExt(filename)
        local extension = string.match(filename, "%.([^%.]+)$")
        if extension then
            return extension
        else
            return false
        end
    end
    
    local dangerousFunctions = {
        -- "LoadResourceFile",
        -- "ExecuteCommand",
        -- "TriggerEvent",
    }
    
    local function ScanDir(resource_name, res_directory, file_name)
        local folder_files = file_name
        local dir = res_directory .. "/" .. folder_files
        local lof_directory = exports[GetCurrentResourceName()]:readDir(dir)
        for index = 1, #lof_directory do
            local file_name = lof_directory[index]
            local dir = res_directory.."/"..folder_files.."/"..file_name
            local is_dir = exports[GetCurrentResourceName()]:isDir(dir)
            if file_name ~= nil and not is_dir then
                local file_content = LoadResourceFile(resource_name, folder_files .. "/" .. file_name)
                if file_content ~= nil then
                    if FileExt(file_name) == "lua" then
                        -- Research of potentially dangerous functions
                        for _, func in ipairs(dangerousFunctions) do
                            if file_content:find(func) then
                                print("Found potentially dangerous function '" .. func .. "' in resource: " .. resource_name .. ", file: " .. file_name)
                            end
                        end
    
                        -- Verify suspicious patterns
                        for i = 1, #signatures do
                            if file_content:find(signatures[i]) then
                                printRed("Found cipher pattern inside resource: "..resource_name..", file: "..file_name, "file: "..file_name)
                                foundSignature = true
                            end
                        end
    
                        -- Verify suspicious strings
                        if file_content:find("eval%(%)") or file_content:find("assert%(%)") or file_content:find("loadstring%(%)") or file_content:find("require%(%)") then
                            printRed("Found suspicious string manipulation in resource: "..resource_name..", file: "..file_name, "file: "..file_name)
                            foundSignature = true
                        end
                    end
                end
            else
                ScanDir(resource_name, res_directory, folder_files .. "/" .. file_name)
            end
        end
    end

    local Resources = GetResources()
    for i = 1, #Resources do
        local resource_name = Resources[i]
        local res_directory = GetResourcePath(resource_name)
        local lof_directory = exports[GetCurrentResourceName()]:readDir(res_directory)
        for index = 1, #lof_directory do
            local file_name = lof_directory[index]
            local is_dir = exports[GetCurrentResourceName()]:isDir(res_directory.."/"..file_name)
            if file_name ~= nil and not is_dir then
                pcall(function()
                    local file_content = LoadResourceFile(resource_name, file_name)
                    if file_content ~= nil then
                        if FileExt(file_name) == "lua" then
                            -- Research of potentially dangerous functions
                            for _, func in ipairs(dangerousFunctions) do
                                if file_content:find(func) then
                                    print("Found potentially dangerous function '" .. func .. "' in resource: " .. resource_name .. ", file: " .. file_name)
                                end
                            end

                            -- Verify suspicious patterns
                            for i = 1, #signatures do
                                if file_content:find(signatures[i]) then
                                    printRed("Found cipher pattern inside resource: "..resource_name..", file: "..file_name, "file: "..file_name)
                                    foundSignature = true
                                end
                            end

                            -- Verify suspicious strings
                            if file_content:find("eval%(%)") or file_content:find("assert%(%)") or file_content:find("loadstring%(%)") or file_content:find("require%(%)") then
                                printRed("Found suspicious string manipulation in resource: "..resource_name..", file: "..file_name, "file: "..file_name)
                                foundSignature = true
                            end
                        end
                    end
                end)
            elseif file_name ~= "node_modules" and file_name ~= "stream" then
                ScanDir(resource_name, res_directory, file_name)
            end
        end
    end

    if not foundSignature then
        print("No cipher patterns or suspicious string manipulations found.")
    end

    print("^0Stopped scanning")
end

RegisterCommand("rescan", function(source, args, rawCommand)
    InitCipherScanner()
    TriggerClientEvent("chat:addMessage", -1, {args = {"^1Server:", "Rescan all resources, researching for cipher patterns and suspicious string manipulations."}})
end, true)
