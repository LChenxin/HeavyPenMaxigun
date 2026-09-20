-- Offline checks for mods/hpmg/dl_probe.lua.
--
-- The probe's risky part is the DL chain parser: it decides whether an
-- arbitrary heap address is a settings buffer. Here it runs against synthetic
-- buffers built by hand, so both acceptance and rejection are checked without
-- attaching to the game. Nothing here touches process memory.

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

-- Build a settings buffer: u32 instance count, then one header+payload each.
local function make_buffer(payloads, type_id, overrides)
    overrides = overrides or {}
    local total = 4
    for _, size in ipairs(payloads) do total = total + 24 + size end
    local buffer = ffi.new('uint8_t[?]', total)
    ffi.cast('uint32_t *', buffer)[0] = overrides.count or #payloads
    local offset = 4
    for index, size in ipairs(payloads) do
        local word = ffi.cast('uint32_t *', buffer + offset)
        word[0] = overrides.magic or MAGIC
        word[1] = overrides.version or 1
        word[2] = (overrides.second_type and index > 1) and overrides.second_type or type_id
        word[3] = size
        word[4] = overrides.wide or 1
        word[5] = overrides.reserved or 0
        offset = offset + 24 + size
    end
    return buffer, total
end

-- Minimal stand-in for the probe's Windows read API, backed by a Lua buffer.
local function fake_api(buffer, size)
    local scratch = ffi.new('uint8_t[64]')
    local words = ffi.cast('uint32_t *', scratch)
    local api = {reads = 0}
    function api.read_header(address, count)
        api.reads = api.reads + 1
        local offset = tonumber(ffi.cast('intptr_t', address) - ffi.cast('intptr_t', buffer))
        if offset < 0 or count > 64 or offset + count > size then return false end
        ffi.copy(scratch, buffer + offset, count)
        return true
    end
    function api.header(index) return words[index] end
    return api
end

-- ---------------------------------------------------------------------------

local source = assert(loadfile('mods/hpmg/dl_probe.lua'))
source()
local probe = rawget(_G, 'HpmgDlProbe')
check(probe ~= nil, 'module publishes its global state')
local internals = probe and probe.internals
check(internals ~= nil, 'module exposes internals for testing')
if not internals then
    print('cannot continue without internals')
    os.exit(1)
end

local measure, describe = internals.measure, internals.describe

print('parser: accepts a well-formed buffer')
do
    -- Eleven instances totalling 79296 bytes: the shape BetterStratagemBounce
    -- verified on this build.
    local payloads = {}
    local remaining = 79296 - 4 - 11 * 24
    for index = 1, 11 do
        payloads[index] = (index == 11) and remaining or math.floor(remaining / 11)
        if index < 11 then remaining = remaining - payloads[index] end
    end
    local buffer, total = make_buffer(payloads, 0x30EB6399)
    equal(total, 79296, 'synthetic buffer is the real stratagem size')
    local api = fake_api(buffer, total)
    local measured, type_id, instances, mixed = measure(api, buffer)
    equal(measured, 79296, 'measured total')
    equal(type_id, 0x30EB6399, 'root type id')
    equal(instances, 11, 'instance count')
    equal(mixed, false, 'all instances share one type')
end

print('parser: names the buffer from its size')
do
    local text = describe(79296, 0x30EB6399, 11, false)
    check(text:find('stratagem_settings', 1, true) ~= nil, 'stratagem size resolves to its file')
    check(describe(93340, 0x11223344, 3, false):find('projectile_settings', 1, true) ~= nil,
          'projectile size resolves to its file')
    check(describe(12345, 0x11223344, 1, false):find('UNMATCHED', 1, true) ~= nil,
          'unknown size is reported as unmatched, not guessed')
    check(describe(79296, 0x30EB6399, 11, true):find('mixed type ids', 1, true) ~= nil,
          'mixed type ids are flagged')
end

print('parser: rejects malformed buffers')
do
    local cases = {
        {'bad magic', {magic = 0x41414141}},
        {'bad version', {version = 7}},
        {'not 64-bit', {wide = 0}},
        {'reserved set', {reserved = 1}},
        {'zero count', {count = 0}},
        {'absurd count', {count = 100000}},
    }
    for _, case in ipairs(cases) do
        local label, overrides = case[1], case[2]
        local buffer, total = make_buffer({64, 64}, 0x30EB6399, overrides)
        local api = fake_api(buffer, total)
        local measured = measure(api, buffer)
        check(measured == nil, 'rejects ' .. label)
    end
end

print('parser: rejects an unreadable address')
do
    local buffer, total = make_buffer({64}, 0x30EB6399)
    local api = fake_api(buffer, total)
    local measured, reason = measure(api, buffer - 4096)
    check(measured == nil, 'rejects an address outside the buffer')
    equal(reason, 'unreadable', 'reports why')
end

print('parser: flags mixed type ids without rejecting')
do
    local buffer, total = make_buffer({64, 64}, 0x30EB6399, {second_type = 0xDEADBEEF})
    local api = fake_api(buffer, total)
    local measured, type_id, instances, mixed = measure(api, buffer)
    equal(measured, total, 'still measures the chain')
    equal(mixed, true, 'mixed flag set')
end

print('parser: read budget stays proportional to instance count')
do
    local buffer, total = make_buffer({32, 32, 32, 32}, 0x30EB6399)
    local api = fake_api(buffer, total)
    measure(api, buffer)
    -- One header probe plus one read per instance.
    equal(api.reads, 5, 'reads per measure')
end

print('config: fingerprints and ground truth agree')
do
    equal(internals.fingerprints[79296], 'stratagem_settings', 'stratagem fingerprint present')
    local truth = internals.ground_truth[0x2791F68]
    check(truth ~= nil, 'stratagem ground truth recorded')
    equal(truth.total, 79296, 'ground truth size')
    equal(internals.fingerprints[truth.total], truth.name, 'ground truth agrees with the fingerprint table')
    check(internals.globals.rva <= 0x2791F68, 'globals section starts at or before the known pointer')
    check(0x2791F68 < internals.globals.rva + internals.globals.size,
          'globals section covers the known pointer')
    check(0x2ACD110 < internals.globals.rva + internals.globals.size,
          'globals section covers the stratagem table')
end

-- ---------------------------------------------------------------------------

print()
if failures == 0 then
    print(string.format('OK  %d checks passed', checks))
else
    print(string.format('FAILED  %d of %d checks', failures, checks))
    os.exit(1)
end
