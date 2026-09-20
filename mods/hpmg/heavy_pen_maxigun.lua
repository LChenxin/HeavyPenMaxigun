-- HD2-Addon: mods/hpmg/heavy_pen_maxigun
--
-- L3: raise the M-1000 Maxigun's armour penetration from 3/3/3/0 (Medium) to
-- 4/4/4/0, the tier the MG-206 HMG and APW-1 AMR already use on this build.
--
-- WHAT IS BEING CHANGED AND WHY IT IS THE RIGHT RECORD
--   Armour penetration is not stored in the projectile record. A projectile
--   record's field +0x3C names a damage-info id, and that id selects a 40-byte
--   run inside the damage_settings buffer:
--
--     +0x00 id   +0x04 damage   +0x08 durable damage
--     +0x0C penetration direct        +0x10 slight angle
--     +0x14 large angle              +0x18 extreme angle
--     +0x1C demolition  +0x20 stagger  +0x24 push
--
--   That layout was not guessed. It was solved from two records whose values a
--   third party published independently (the HMG/AMR analysis distributed with
--   HMG-AMR-Rounds-v3), and both reproduce exactly here:
--
--     id 199  150/35  4/4/4/0  15/25/20   MG-206 HMG
--     id 200  450/225 4/4/4/0  20/25/25   APW-1 AMR
--
--   The Maxigun's record is id 123: 80 damage, 18 durable, 3/3/3/0. The pair
--   (80, 18) occurs exactly once in the whole 48,664-byte buffer, and 3/3/3/0
--   is Medium/Medium/Medium/Unarmored, which is what the weapon is documented
--   to have. Exactly one projectile record points at damage-info 123, so this
--   change cannot leak into another weapon the way a shared projectile record
--   would.
--
--   The identification still rests on that stat combination being unique, not
--   on a name -- damage_settings carries no strings. Firing the weapon is the
--   only real confirmation.
--
-- SAFETY
--   Three independent anchors are checked before any write: the target record
--   in its vanilla state, plus the HMG and AMR records. If any one of them
--   disagrees, nothing is written. Only 12 bytes are ever written, only into
--   committed private read/write pages, never into executable or mapped module
--   memory. No game file is modified; removing the mod restores stock values on
--   the next launch.

if rawget(_G, 'HeavyPenMaxigun') then return end

local ffi = require('ffi')

local BUILD = {
    revision = 'heavy_pen_maxigun-2',
    exe_sha256 = 'A09FF52663E73B94FB0CAC0DCB5BA84FFD10ECF44F74A8921AC66AF923988CC3',
    game_sha256 = 'CC75948D90FDFDE259DCB519E9933DB7FFA3CCB281CE4FB89E6B1B011557470C',
}

-- damage_settings: global pointer, decrypted size, root type, instance count.
local BUFFER = {rva = 0x02791748, size = 48664, type_id = 0xEB1433DA, instances = 2}
local DL_MAGIC = 0x444C444C

local TARGET = {
    offset = 0x02664,
    -- id, damage, durable, pen x4, demolition, stagger, push
    vanilla = {123, 80, 18, 3, 3, 3, 0, 10, 15, 12},
}

-- Penetration occupies three consecutive dwords starting 0x0C into the record.
-- The extreme-angle slot at +0x18 stays 0: the weapon is documented as
-- Unarmored there, and HMG and AMR are 0 there too.
local PEN_OFFSET = 0x0C
local PEN_COUNT = 3
local PEN_VALUE = 4
local DAMAGE_OFFSET = 0x04

-- Off. This mod changes penetration and nothing else.
--
-- The write plan below can carry a damage change as well, which would be an
-- unmissable way to prove the engine actually reads this record -- the log's
-- readback only proves the bytes landed. It stays nil because altering damage
-- was not asked for. Magazine capacity, the other obvious candidate, is not
-- reachable at all: it lives in weapon component data, which the HMG/AMR
-- analysis in samplefile/ shows two live tests failing to find in readable
-- runtime memory.
local TEST_DAMAGE = nil

-- Records whose values were published independently; they pin the layout.
local ANCHORS = {
    {offset = 0x03B2C, name = 'MG-206 HMG', values = {199, 150, 35, 4, 4, 4, 0, 15, 25, 20}},
    {offset = 0x03B78, name = 'APW-1 AMR', values = {200, 450, 225, 4, 4, 4, 0, 20, 25, 25}},
}

local RECHECK_TICKS = 600

local state = {
    revision = BUILD.revision,
    phase = 'waiting_for_update',
    status = 'pending',
    updates = 0, applied = 0, reapplied = 0, checks = 0,
}
rawset(_G, 'HeavyPenMaxigun', state)

local function report(message)
    state.status = message
    print('[HeavyPenMaxigun] ' .. BUILD.revision .. ': ' .. message)
    pcall(function()
        local loader = rawget(_G, 'CowboyBingusModLoader')
        local file = loader and loader.open_log and loader.open_log('HeavyPenMaxigun.log')
        if not file then return end
        file:write(BUILD.revision .. '\n')
        file:write(string.format('updates=%d applied=%d reapplied=%d checks=%d\n',
                                 state.updates, state.applied, state.reapplied, state.checks))
        file:write(message .. '\n')
        if state.detail then file:write(state.detail .. '\n') end
        file:close()
    end)
end

local function create_api()
    assert(ffi.abi('64bit'), 'Windows x64 is required')
    ffi.cdef [[
        void *GetModuleHandleA(const char *name);
        uint32_t GetModuleFileNameW(void *module, uint16_t *path, uint32_t capacity);
        void *GetCurrentProcess(void);
        int ReadProcessMemory(void *process, const void *address, void *buffer, size_t size, size_t *read);
        int WriteProcessMemory(void *process, void *address, const void *buffer, size_t size, size_t *written);
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
        typedef struct {
            void *base; void *allocation_base; uint32_t allocation_protection;
            uint16_t partition; uint16_t reserved; size_t size;
            uint32_t state; uint32_t protection; uint32_t type;
        } HpmgPenRegion;
        size_t VirtualQuery(const void *address, void *region, size_t size);
    ]]
    local kernel, bcrypt = ffi.load('kernel32'), ffi.load('bcrypt')
    local process = kernel.GetCurrentProcess()
    local api = {}

    local scratch = ffi.new('uint8_t[256]')
    local words = ffi.cast('uint32_t *', scratch)
    local count = ffi.new('size_t[1]')

    function api.module(name)
        local handle = kernel.GetModuleHandleA(name)
        if handle == nil then return nil end
        return ffi.cast('uint8_t *', handle)
    end

    function api.read(address, size)
        if size < 1 or size > 256 then return false end
        if kernel.ReadProcessMemory(process, address, scratch, size, count) == 0 then return false end
        return count[0] == size
    end

    function api.word(index) return words[index] end

    function api.pointer_at(address)
        if not api.read(address, 8) then return nil end
        local value = ffi.cast('uint64_t *', scratch)[0]
        if value < 0x10000ULL or value >= 0x800000000000ULL then return nil end
        return ffi.cast('uint8_t *', value)
    end

    -- Settings must already be committed, private, plain read/write data.
    -- Executable pages and mapped module images are refused outright.
    function api.writable_data(address, size)
        if size < 1 or size > 4096 then return false end
        local region = ffi.new('HpmgPenRegion[1]')
        local wanted = ffi.sizeof(region[0])
        local cursor = ffi.cast('uint8_t *', address)
        local remaining = size
        while remaining > 0 do
            if kernel.VirtualQuery(cursor, region, wanted) ~= wanted then return false end
            if region[0].state ~= 0x1000 or region[0].type ~= 0x20000
                or region[0].protection ~= 4 then return false end
            -- region.base is void *, which LuaJIT refuses to do arithmetic on.
            -- Work from the region size and how far into it the cursor already
            -- sits, the way the sample mods do, instead of base + size.
            local into = tonumber(ffi.cast('intptr_t', cursor) - ffi.cast('intptr_t', region[0].base))
            local available = tonumber(region[0].size) - into
            if available <= 0 then return false end
            local step = math.min(available, remaining)
            cursor = cursor + step
            remaining = remaining - step
        end
        return true
    end

    function api.write_words(address, values)
        local size = #values * 4
        if not api.writable_data(address, size) then return false, 'not writable private data' end
        local payload = ffi.new('uint32_t[?]', #values)
        for index, value in ipairs(values) do payload[index - 1] = value end
        local written = ffi.new('size_t[1]')
        if kernel.WriteProcessMemory(process, address, payload, size, written) == 0 then
            return false, 'WriteProcessMemory failed'
        end
        if written[0] ~= size then return false, 'short write' end
        return true
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

-- ---------------------------------------------------------------------------

local function read_record(api, buffer, offset, length)
    if not api.read(buffer + offset, length * 4) then return nil end
    local out = {}
    for index = 1, length do out[index] = api.word(index - 1) end
    return out
end

local function same(a, b)
    if not a or not b or #a ~= #b then return false end
    for index = 1, #a do
        if a[index] ~= b[index] then return false end
    end
    return true
end

local function show(values)
    if not values then return 'unreadable' end
    return table.concat(values, ',')
end

-- Confirm the buffer really is damage_settings before trusting any offset.
local function validate_buffer(api, buffer)
    if not api.read(buffer, 28) then return false, 'buffer unreadable' end
    if api.word(0) ~= BUFFER.instances then
        return false, 'instance count ' .. api.word(0)
    end
    if api.word(1) ~= DL_MAGIC then return false, 'no DL magic' end
    if api.word(2) ~= 1 then return false, 'DL version ' .. api.word(2) end
    if api.word(3) ~= BUFFER.type_id then
        return false, string.format('type 0x%08X', api.word(3))
    end
    return true
end

-- Each entry is one contiguous run of dwords to write, with the values it is
-- replacing so a failed pass can put them back. Penetration and damage are not
-- adjacent, so they are separate writes rather than one wider one that would
-- also rewrite durable damage for no reason.
local function build_plan()
    local expected = {}
    for index, value in ipairs(TARGET.vanilla) do expected[index] = value end

    local plan = {{offset = PEN_OFFSET,
                   after = {PEN_VALUE, PEN_VALUE, PEN_VALUE},
                   before = {expected[4], expected[5], expected[6]},
                   label = 'penetration'}}
    expected[4], expected[5], expected[6] = PEN_VALUE, PEN_VALUE, PEN_VALUE

    if TEST_DAMAGE then
        plan[#plan + 1] = {offset = DAMAGE_OFFSET,
                           after = {TEST_DAMAGE}, before = {expected[2]},
                           label = 'TEST damage'}
        expected[2] = TEST_DAMAGE
    end
    return plan, expected
end

local PLAN, PATCHED = build_plan()
TARGET.patched = PATCHED

-- Returns 'vanilla', 'patched', or nil plus a reason. Anchors are checked on
-- every pass, not just the first: they are what says the layout has not moved.
local function inspect(api, buffer)
    local ok, reason = validate_buffer(api, buffer)
    if not ok then return nil, 'buffer: ' .. reason end

    for _, anchor in ipairs(ANCHORS) do
        local values = read_record(api, buffer, anchor.offset, #anchor.values)
        if not same(values, anchor.values) then
            return nil, string.format('anchor %s at 0x%05X reads %s, expected %s',
                                      anchor.name, anchor.offset, show(values), show(anchor.values))
        end
    end

    local record = read_record(api, buffer, TARGET.offset, #TARGET.vanilla)
    if same(record, TARGET.vanilla) then return 'vanilla' end
    if same(record, TARGET.patched) then return 'patched' end
    return nil, string.format('target at 0x%05X reads %s, expected %s',
                              TARGET.offset, show(record), show(TARGET.vanilla))
end

local function apply(api, game)
    local buffer = api.pointer_at(game + BUFFER.rva)
    if not buffer then
        return nil, string.format('no damage_settings pointer at game.dll+0x%08X', BUFFER.rva)
    end

    local condition, reason = inspect(api, buffer)
    if not condition then return nil, reason end
    if condition == 'patched' then return 'already', buffer end

    local done = {}
    for _, step in ipairs(PLAN) do
        local written, problem = api.write_words(buffer + TARGET.offset + step.offset, step.after)
        if not written then
            -- Unwind whatever already landed before giving up.
            for index = #done, 1, -1 do
                api.write_words(buffer + TARGET.offset + done[index].offset, done[index].before)
            end
            return nil, string.format('write refused on %s: %s', step.label, tostring(problem))
        end
        done[#done + 1] = step
    end

    local after = read_record(api, buffer, TARGET.offset, #TARGET.patched)
    if not same(after, TARGET.patched) then
        local restored = true
        for index = #done, 1, -1 do
            restored = api.write_words(buffer + TARGET.offset + done[index].offset,
                                       done[index].before) and restored
        end
        return nil, string.format('readback %s, expected %s; rollback=%s',
                                  show(after), show(TARGET.patched), tostring(restored))
    end
    return 'applied', buffer
end

state.internals = {create_api = create_api, inspect = inspect, apply = apply, same = same, read_record = read_record,
                   target = TARGET, anchors = ANCHORS, buffer = BUFFER, plan = PLAN,
                   pen_offset = PEN_OFFSET, pen_count = PEN_COUNT, pen_value = PEN_VALUE,
                   damage_offset = DAMAGE_OFFSET, test_damage = TEST_DAMAGE}

-- ---------------------------------------------------------------------------

local previous_update = update
local self_update
local api, game
local idle = 0

self_update = function(dt, ...)
    state.updates = state.updates + 1

    if state.phase == 'waiting_for_update' then
        local ok, result, module = pcall(function()
            local created = create_api()
            local exe, dll = created.module(nil), created.module('game.dll')
            assert(exe and dll, 'Required game modules unavailable')
            assert(created.module_hash(exe) == BUILD.exe_sha256,
                   'Unsupported executable; no change applied')
            assert(created.module_hash(dll) == BUILD.game_sha256,
                   'Unsupported game module; no change applied')
            return created, dll
        end)
        if not ok then
            state.phase = 'inactive'
            report('inactive: ' .. tostring(result))
        else
            api, game = result, module
            state.phase = 'applying'
        end

    elseif state.phase == 'applying' then
        local ok, outcome, detail = pcall(apply, api, game)
        if not ok then
            state.phase = 'inactive'
            report('inactive: ' .. tostring(outcome))
        elseif not outcome then
            -- Settings may not be loaded yet; keep looking rather than give up.
            idle = idle + 1
            state.detail = tostring(detail)
            if idle >= RECHECK_TICKS then
                idle = 0
                report('waiting: ' .. tostring(detail))
            end
        else
            state.applied = state.applied + 1
            state.phase = 'monitoring'
            idle = 0
            local what = 'penetration 3/3/3/0 -> 4/4/4/0 on damage-info 123'
            if TEST_DAMAGE then
                what = what .. string.format('; TEST damage %d -> %d',
                                             TARGET.vanilla[2], TEST_DAMAGE)
            end
            report(outcome == 'already' and ('already applied: ' .. what) or ('applied: ' .. what))
        end

    elseif state.phase == 'monitoring' then
        idle = idle + 1
        if idle >= RECHECK_TICKS then
            idle = 0
            state.checks = state.checks + 1
            local ok, outcome, detail = pcall(apply, api, game)
            if ok and outcome == 'applied' then
                state.reapplied = state.reapplied + 1
                report('settings reloaded; penetration reapplied')
            elseif ok and not outcome then
                state.detail = tostring(detail)
            end
        end
    end

    if previous_update then return previous_update(dt, ...) end
end
update = self_update

report('loaded; waiting for the first update tick')
