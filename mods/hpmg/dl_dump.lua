-- HD2-Addon: mods/hpmg/dl_dump
--
-- L2.5: copy selected decrypted settings buffers out of the process so their
-- record layout can be worked out offline, where real tooling is available.
--
-- The RVAs below came from mods/hpmg/dl_probe.lua, which rediscovered
-- BetterStratagemBounce's verified stratagem pointer on its own before any of
-- the others were trusted. stratagem_settings is dumped here as a control: its
-- record size (400) and navigation flag offset (0x170) are already known, so
-- the offline analyser has something with a right answer to be checked against.
--
-- Each dump carries the buffer's base address, because the serialized data
-- contains absolute pointers that datalibrary fixed up at load time. Without
-- the base there is no way to turn them back into offsets.
--
-- This module only ever reads process memory. It writes nothing back.

if rawget(_G, 'HpmgDlDump') then return end

local ffi = require('ffi')

local BUILD = {
    revision = 'dl_dump-1',
    exe_sha256 = 'A09FF52663E73B94FB0CAC0DCB5BA84FFD10ECF44F74A8921AC66AF923988CC3',
    game_sha256 = 'CC75948D90FDFDE259DCB519E9933DB7FFA3CCB281CE4FB89E6B1B011557470C',
}

local DL_MAGIC = 0x444C444C
local MAX_INSTANCES = 512
local MAX_DUMP = 1024 * 1024

-- rva: game.dll global holding the buffer pointer. expect: decrypted size, i.e.
-- the shipped .dl_bin size minus the 48-byte crypto framing.
local TARGETS = {
    {rva = 0x02791848, name = 'projectile_settings', expect = 93340},
    {rva = 0x02791748, name = 'damage_settings', expect = 48664},
    {rva = 0x027911E8, name = 'weapon_customization_settings', expect = 28784},
    {rva = 0x02791F68, name = 'stratagem_settings', expect = 79296},
}

local state = {revision = BUILD.revision, phase = 'waiting_for_update', updates = 0, results = {}}
rawset(_G, 'HpmgDlDump', state)

local function report(message)
    print('[HpmgDlDump] ' .. BUILD.revision .. ': ' .. message)
end

-- Struct tags are global to the LuaJIT VM; other mods declare their own region
-- layout, so this module avoids defining any struct at all.
local function create_api()
    assert(ffi.abi('64bit'), 'Windows x64 is required')
    ffi.cdef [[
        void *GetModuleHandleA(const char *name);
        uint32_t GetModuleFileNameW(void *module, uint16_t *path, uint32_t capacity);
        void *GetCurrentProcess(void);
        int ReadProcessMemory(void *process, const void *address, void *buffer, size_t size, size_t *read);
        void *CreateFileW(const uint16_t *path, uint32_t access, uint32_t share, void *security,
                          uint32_t disposition, uint32_t flags, void *template_file);
        int ReadFile(void *file, void *buffer, uint32_t size, uint32_t *read, void *overlapped);
        int CloseHandle(void *handle);
        int32_t BCryptOpenAlgorithmProvider(void **algorithm, const uint16_t *name,
                                            const uint16_t *provider, uint32_t flags);
        int32_t BCryptCloseAlgorithmProvider(void *algorithm, uint32_t flags);
        int32_t BCryptCreateHash(void *algorithm, void **hash, void *object, uint32_t object_size,
                                 const void *secret, uint32_t secret_size, uint32_t flags);
        int32_t BCryptHashData(void *hash, const void *data, uint32_t size, uint32_t flags);
        int32_t BCryptFinishHash(void *hash, void *digest, uint32_t size, uint32_t flags);
        int32_t BCryptDestroyHash(void *hash);
    ]]
    local kernel, bcrypt = ffi.load('kernel32'), ffi.load('bcrypt')
    local process = kernel.GetCurrentProcess()
    local api = {}

    local big = ffi.new('uint8_t[?]', MAX_DUMP)
    local small = ffi.new('uint8_t[64]')
    local small_words = ffi.cast('uint32_t *', small)
    local count = ffi.new('size_t[1]')

    function api.module(name)
        local handle = kernel.GetModuleHandleA(name)
        if handle == nil then return nil end
        return ffi.cast('uint8_t *', handle)
    end

    function api.read_header(address, size)
        if size > 64 then return false end
        if kernel.ReadProcessMemory(process, address, small, size, count) == 0 then return false end
        return count[0] == size
    end

    function api.header(index) return small_words[index] end

    function api.pointer_at(address)
        if not api.read_header(address, 8) then return nil end
        local value = ffi.cast('uint64_t *', small)[0]
        if value < 0x10000ULL or value >= 0x800000000000ULL then return nil end
        return ffi.cast('uint8_t *', value)
    end

    -- Copy `size` bytes into the shared dump buffer and hand back a Lua string.
    function api.capture(address, size)
        if size < 1 or size > MAX_DUMP then return nil end
        if kernel.ReadProcessMemory(process, address, big, size, count) == 0 then return nil end
        if count[0] ~= size then return nil end
        return ffi.string(big, size)
    end

    function api.module_hash(module)
        local path = ffi.new('uint16_t[32768]')
        local length = kernel.GetModuleFileNameW(module, path, 32768)
        assert(length > 0 and length < 32768, 'Cannot resolve module file')
        local file = kernel.CreateFileW(path, 0x80000000, 7, nil, 3, 0x08000000, nil)
        assert(file ~= ffi.cast('void *', -1), 'Cannot read module file')
        local algorithm, hash = ffi.new('void *[1]'), ffi.new('void *[1]')
        local ok, result = pcall(function()
            local name = ffi.new('uint16_t[7]', {83, 72, 65, 50, 53, 54, 0})
            assert(bcrypt.BCryptOpenAlgorithmProvider(algorithm, name, nil, 0) == 0, 'SHA256 unavailable')
            assert(bcrypt.BCryptCreateHash(algorithm[0], hash, nil, 0, nil, 0, 0) == 0, 'SHA256 creation failed')
            local buffer, read = ffi.new('uint8_t[1048576]'), ffi.new('uint32_t[1]')
            while true do
                assert(kernel.ReadFile(file, buffer, 1048576, read, nil) ~= 0, 'Module file read failed')
                if read[0] == 0 then break end
                assert(bcrypt.BCryptHashData(hash[0], buffer, read[0], 0) == 0, 'SHA256 update failed')
            end
            local digest, hex = ffi.new('uint8_t[32]'), {}
            assert(bcrypt.BCryptFinishHash(hash[0], digest, 32, 0) == 0, 'SHA256 finish failed')
            for i = 0, 31 do hex[#hex + 1] = string.format('%02X', digest[i]) end
            return table.concat(hex)
        end)
        if hash[0] ~= nil then bcrypt.BCryptDestroyHash(hash[0]) end
        if algorithm[0] ~= nil then bcrypt.BCryptCloseAlgorithmProvider(algorithm[0], 0) end
        kernel.CloseHandle(file)
        if not ok then error(result) end
        return result
    end

    return api
end

-- Same chain walk as dl_probe: confirm this really is a DL buffer and size it.
local function measure(api, address)
    if not api.read_header(address, 28) then return nil, 'unreadable' end
    local instances = api.header(0)
    if instances < 1 or instances > MAX_INSTANCES then return nil, 'count' end
    if api.header(1) ~= DL_MAGIC then return nil, 'magic' end
    if api.header(2) ~= 1 then return nil, 'version' end
    if api.header(5) ~= 1 then return nil, 'not 64-bit' end
    if api.header(6) ~= 0 then return nil, 'reserved' end
    local type_id = api.header(3)
    local offset = 4
    for _ = 1, instances do
        if not api.read_header(address + offset, 24) then return nil, 'chain unreadable' end
        if api.header(0) ~= DL_MAGIC then return nil, 'chain magic' end
        if api.header(1) ~= 1 then return nil, 'chain version' end
        offset = offset + 24 + api.header(3)
        if offset > MAX_DUMP then return nil, 'oversize' end
    end
    return offset, type_id, instances
end

-- 32-byte dump header, then the buffer verbatim. The base address is what lets
-- the offline analyser turn the buffer's absolute pointers back into offsets.
local function dump_header(address, size, type_id, instances)
    local header = ffi.new('uint8_t[32]')
    ffi.copy(header, 'HPMGDUMP', 8)
    local words = ffi.cast('uint32_t *', header + 8)
    words[0] = 1
    words[1] = type_id
    local wide = ffi.cast('uint64_t *', header + 16)
    wide[0] = ffi.cast('uintptr_t', address)
    words = ffi.cast('uint32_t *', header + 24)
    words[0] = size
    words[1] = instances
    return ffi.string(header, 32)
end

local function run(state)
    local api = create_api()
    local exe, game = api.module(nil), api.module('game.dll')
    assert(exe and game, 'Required game modules unavailable')
    assert(api.module_hash(exe) == BUILD.exe_sha256, 'Unsupported executable')
    assert(api.module_hash(game) == BUILD.game_sha256, 'Unsupported game module')

    local loader = rawget(_G, 'CowboyBingusModLoader')
    local directory = loader and loader.log_directory
    if not directory then
        -- open_log creates the shared directory as a side effect.
        if loader and loader.open_log then
            local probe = loader.open_log('HpmgDlDump.log')
            if probe then probe:close() end
            directory = loader.log_directory
        end
    end
    assert(directory, 'Shared log directory unavailable; loader v14+ required')

    for _, target in ipairs(TARGETS) do
        local note
        local address = api.pointer_at(game + target.rva)
        if not address then
            note = 'no pointer at that global'
        else
            local total, type_id, instances = measure(api, address)
            if not total then
                note = 'not a DL buffer: ' .. tostring(type_id)
            elseif total ~= target.expect then
                note = string.format('size %d, expected %d; refusing to dump a buffer we cannot identify',
                                     total, target.expect)
            else
                local bytes = api.capture(address, total)
                if not bytes then
                    note = 'capture failed'
                else
                    local path = directory .. '/HpmgDump_' .. target.name .. '.bin'
                    local file, reason = io.open(path, 'wb')
                    if not file then
                        note = 'cannot write: ' .. tostring(reason)
                    else
                        file:write(dump_header(address, total, type_id, instances))
                        file:write(bytes)
                        file:close()
                        note = string.format('dumped %d bytes, type 0x%08X, %d instance(s), base 0x%012X',
                                             total, type_id, instances,
                                             tonumber(ffi.cast('uintptr_t', address)))
                    end
                end
            end
        end
        state.results[#state.results + 1] = {name = target.name, rva = target.rva, note = note}
        report(target.name .. ': ' .. note)
    end

    local file = loader.open_log and loader.open_log('HpmgDlDump.log')
    if file then
        file:write(BUILD.revision .. '\n')
        file:write('directory: ' .. directory .. '\n\n')
        for _, row in ipairs(state.results) do
            file:write(string.format('game.dll+0x%08X  %-32s %s\n', row.rva, row.name, row.note))
        end
        file:close()
    end
end

state.internals = {measure = measure, dump_header = dump_header, targets = TARGETS}

local previous_update = update
local self_update
self_update = function(dt, ...)
    state.updates = state.updates + 1
    if state.phase == 'waiting_for_update' then
        local ok, reason = pcall(run, state)
        state.phase = ok and 'complete' or ('failed: ' .. tostring(reason))
        if not ok then report(state.phase) end
        if update == self_update then update = previous_update or function() end end
    end
    if previous_update then return previous_update(dt, ...) end
end
update = self_update

report('loaded; will dump on the first update tick')
