-- Offline checks for mods/hpmg/dl_dump.lua.
--
-- Two things can silently go wrong here. The chain walk might accept a buffer
-- that is not a settings blob, and the 32-byte dump header might not be what
-- tools/analyze_dl.py expects -- a mismatch neither side would notice until the
-- analysis quietly produced nonsense. Both are checked, and the header is also
-- written to tests/_artifacts so the Python side can parse it for real.

local ffi = require('ffi')

local MAGIC = 0x444C444C
local failures = 0
local checks = 0

local function check(condition, description)
    checks = checks + 1
    if not condition then
        failures = failures + 1
        print('  FAIL ' .. description)
    end
end

local function equal(actual, expected, description)
    check(actual == expected,
          string.format('%s (got %s, expected %s)', description, tostring(actual), tostring(expected)))
end

local function make_buffer(payloads, type_id, overrides)
    overrides = overrides or {}
    local total = 4
    for _, size in ipairs(payloads) do total = total + 24 + size end
    local buffer = ffi.new('uint8_t[?]', total)
    ffi.cast('uint32_t *', buffer)[0] = overrides.count or #payloads
    local offset = 4
    for _, size in ipairs(payloads) do
        local word = ffi.cast('uint32_t *', buffer + offset)
        word[0] = overrides.magic or MAGIC
        word[1] = overrides.version or 1
        word[2] = type_id
        word[3] = size
        word[4] = overrides.wide or 1
        word[5] = overrides.reserved or 0
        offset = offset + 24 + size
    end
    return buffer, total
end

local function fake_api(buffer, size)
    local scratch = ffi.new('uint8_t[64]')
    local words = ffi.cast('uint32_t *', scratch)
    local api = {}
    function api.read_header(address, count)
        local offset = tonumber(ffi.cast('intptr_t', address) - ffi.cast('intptr_t', buffer))
        if offset < 0 or count > 64 or offset + count > size then return false end
        ffi.copy(scratch, buffer + offset, count)
        return true
    end
    function api.header(index) return words[index] end
    return api
end

-- ---------------------------------------------------------------------------

assert(loadfile('mods/hpmg/dl_dump.lua'))()
local module = rawget(_G, 'HpmgDlDump')
check(module ~= nil, 'module publishes its global state')
local internals = module and module.internals
check(internals ~= nil, 'module exposes internals')
if not internals then os.exit(1) end

local measure, dump_header = internals.measure, internals.dump_header

print('chain walk: accepts and sizes a well-formed buffer')
do
    local buffer, total = make_buffer({128, 256, 64}, 0xBD4042C2)
    local api = fake_api(buffer, total)
    local measured, type_id, instances = measure(api, buffer)
    equal(measured, total, 'measured total')
    equal(type_id, 0xBD4042C2, 'type id')
    equal(instances, 3, 'instance count')
end

print('chain walk: rejects malformed buffers')
do
    local cases = {
        {'bad magic', {magic = 0x41414141}},
        {'bad version', {version = 9}},
        {'not 64-bit', {wide = 0}},
        {'reserved set', {reserved = 1}},
        {'zero count', {count = 0}},
    }
    for _, case in ipairs(cases) do
        local buffer, total = make_buffer({64, 64}, 0xBD4042C2, case[2])
        check(measure(fake_api(buffer, total), buffer) == nil, 'rejects ' .. case[1])
    end
end

print('targets: every entry names a size the probe actually reported')
do
    local expected = {
        projectile_settings = 93340,
        damage_settings = 48664,
        weapon_customization_settings = 28784,
        stratagem_settings = 79296,
    }
    local seen = 0
    for _, target in ipairs(internals.targets) do
        equal(target.expect, expected[target.name], target.name .. ' expected size')
        check(target.rva > 0x02394000 and target.rva < 0x02394000 + 7622788,
              target.name .. ' rva lies inside the globals section')
        seen = seen + 1
    end
    equal(seen, 4, 'target count')
    -- The control must stay in the list; without it nothing validates the rest.
    local has_control = false
    for _, target in ipairs(internals.targets) do
        if target.name == 'stratagem_settings' and target.rva == 0x02791F68 then has_control = true end
    end
    check(has_control, 'stratagem control target present at its verified RVA')
end

print('dump header: 32 bytes, fields where the analyser looks for them')
do
    local address = ffi.cast('uint8_t *', 0x1CFB4E20000ULL)
    local header = dump_header(address, 79296, 0x30EB6399, 11)
    equal(#header, 32, 'header size')
    equal(header:sub(1, 8), 'HPMGDUMP', 'magic')

    local raw = ffi.new('uint8_t[32]')
    ffi.copy(raw, header, 32)
    local words = ffi.cast('uint32_t *', raw)
    equal(words[2], 1, 'version at +8')
    equal(words[3], 0x30EB6399, 'type id at +12')
    equal(tonumber(ffi.cast('uint64_t *', raw + 16)[0]), 0x1CFB4E20000, 'base address at +16')
    equal(words[6], 79296, 'size at +24')
    equal(words[7], 11, 'instance count at +28')

    -- Hand a complete, parseable dump to the Python side.
    local payload = 256
    local total = 4 + 24 + payload
    local buffer = ffi.new('uint8_t[?]', total)
    ffi.cast('uint32_t *', buffer)[0] = 1
    local word = ffi.cast('uint32_t *', buffer + 4)
    word[0] = MAGIC; word[1] = 1; word[2] = 0xBD4042C2; word[3] = payload; word[4] = 1; word[5] = 0
    local file = io.open('tests/_artifacts/lua_dump.bin', 'wb')
    check(file ~= nil, 'can write the cross-language artifact')
    if file then
        file:write(dump_header(ffi.cast('uint8_t *', 0x1000000ULL), total, 0xBD4042C2, 1))
        file:write(ffi.string(buffer, total))
        file:close()
    end
end

-- ---------------------------------------------------------------------------

print()
if failures == 0 then
    print(string.format('OK  %d checks passed', checks))
else
    print(string.format('FAILED  %d of %d checks', failures, checks))
    os.exit(1)
end
