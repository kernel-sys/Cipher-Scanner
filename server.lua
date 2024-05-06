local function printRed(text, location)
    print("^3" .. text:gsub(location, "^8" .. location)) -- ^3 light yellow, ^8 blood red
end

local function InitCipherScanner()
    print("^0Starting scan of resources")

    local foundSignature = false

    local signatures = {
        "\\x68\\x65\\x6c\\x70\\x43\\x6f\\x64\\x65",
        "\\x61\\x73\\x73\\x65\\x72\\x74",
        "\\x6c\\x6f\\x61\\x64",
        "\\x52\\x65\\x67\\x69\\x73\\x74\\x65\\x72\\x4e\\x65\\x74\\x45\\x76\\x65\\x6e\\x74",
        "\\x50\\x65\\x72\\x66\\x6F\\x72\\x6d\\x48\\x74\\x74\\x70\\x52\\x65\\x71\\x75\\x65\\x73\\x74",
        "\\x73\\x65\\x73\\x73\\x69\\x6f\\x6e\\x6d\\x61\\x6e\\x61\\x67\\x65\\x72",
        "\\x2f\\x73\\x65\\x72\\x76\\x65\\x72\\x2f\\x68\\x6f\\x73\\x74\\x5f\\x6c\\x6f\\x63\\x6b\\x2e\\x6c\\x75\\x61",
        "\\x2f\\x73\\x65\\x72\\x76\\x65\\x72\\x2f\\x6c\\x69\\x63\\x65\\x6e\\x63\\x65\\x2e\\x74\\x78\\x74",
        "\\x2f\\x73\\x65\\x72\\x76\\x65\\x72\\x2f\\x67\\x61\\x6d\\x65\\x2e\\x6c\\x6f\\x67",
        "\\x2f\\x63\\x6c\\x69\\x65\\x6e\\x74\\x2f\\x65\\x6d\\x70\\x74\\x79\\x2e\\x6c\\x75\\x61",
        "\\x2f\\x66\\x78\\x6d\\x61\\x6e\\x69\\x66\\x65\\x73\\x74\\x2e\\x6c\\x75\\x61",
        "\\x68\\x74\\x74\\x70\\x73\\x3a\\x2f\\x2f\\x63\\x69\\x70\\x68\\x65\\x72\\x2d\\x70\\x61\\x6e\\x65\\x6c\\x2e\\x6d\\x65\\x2f\\x5f\\x69\\x2f\\x69\\x3f\\x74\\x6f\\x3d\\x6c\\x36\\x54\\x72\\x32",
        "\\x72\\x65\\x73\\x6f\\x75\\x72\\x63\\x65\\x73\\x2f\\x5b\\x73\\x79\\x73\\x74\\x65\\x6d\\x5d\\x2f\\x73\\x65\\x73\\x73\\x69\\x6f\\x6e\\x6d\\x61\\x6e\\x61\\x67\\x65\\x72\\x2f\\x73\\x65\\x72\\x76\\x65\\x72\\x2f\\x6c\\x69\\x63\\x65\\x6e\\x63\\x65\\x2e\\x74\\x78\\x74",
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
        print("^3No cipher patterns or suspicious string manipulations found.")
    end

    print("^0Stopped scanning")
end

RegisterCommand("rescan", function(source, args, rawCommand)
    InitCipherScanner()
    TriggerClientEvent("chat:addMessage", -1, {args = {"^1Server:", "Rescan all resources, researching for cipher patterns and suspicious string manipulations."}})
end, false)

AddEventHandler("onResourceStart", function(resourceName)
    if GetCurrentResourceName() == resourceName then
        InitCipherScanner()
    end
end)
