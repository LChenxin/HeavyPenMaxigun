-- HD2-Addon: mods/hpmg/hello_test
--
-- L1: startup-chain check only. Reads nothing, writes nothing, changes no gameplay.
-- Its whole job is to prove that packaging -> deploy -> discovery -> require works.

local loader = rawget(_G, 'CowboyBingusModLoader')

-- Discovery can hand the same resource to require more than once if another
-- copy is deployed; keep initialization idempotent the way the sample mods do.
if rawget(_G, 'HpmgHelloTest') then return end

local state = {
    api = loader and loader.api,
    loader_version = loader and loader.version,
    discovery = loader and loader.discovery,
    updates = 0,
}
rawset(_G, 'HpmgHelloTest', state)

local function line(key, value)
    return key .. '=' .. tostring(value)
end

local summary = table.concat({
    line('loader_api', state.api),
    line('loader_version', state.loader_version),
    line('discovery', state.discovery),
    line('stingray', stingray ~= nil),
    line('ffi', pcall(require, 'ffi')),
}, ' ')

print('[HpmgHelloTest] ' .. summary)

-- open_log exists from loader v14 onward; guard it so an older loader cannot
-- turn a missing helper into a startup error.
pcall(function()
    local file = loader and loader.open_log and loader.open_log('HpmgHelloTest.log')
    if not file then return end
    file:write('mods/hpmg/hello_test\n')
    file:write(summary .. '\n')
    file:write('modules seen by loader:\n')
    if loader and loader.modules then
        for name, status in pairs(loader.modules) do
            file:write('  ' .. name .. ': ' .. tostring(status) .. '\n')
        end
    end
    file:close()
end)

-- Wrap the update callback exactly like archive_loader.lua does: remember the
-- previous owner, forward to it, and hand ownership back once we are done.
local previous_update = update
local self_update
self_update = function(dt, ...)
    state.updates = state.updates + 1
    if state.updates == 1 then
        print('[HpmgHelloTest] first update tick reached; dt=' .. tostring(dt))
    end
    if state.updates >= 2 then
        -- Only release the callback if we still own it; a later mod may have wrapped us.
        if update == self_update then update = previous_update or function() end end
    end
    if previous_update then return previous_update(dt, ...) end
end
update = self_update
