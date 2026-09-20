-- Offline checks for mods/hpmg/dl_hunt.lua.
--
-- The point of this module is that it reports what it threw away, so the tests
-- are mostly about the failure paths. measure() returns
--     total, type_id, instances, mixed      on success
--     nil,   reason,  had_header            on failure
-- and the caller uses that third value to decide whether a rejection is worth
-- recording. Getting it backwards would silently empty the near-miss report,
-- which is exactly the kind of quiet failure this module exists to prevent.

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

assert(loadfile('mods/hpmg/dl_hunt.lua'))()
local module = rawget(_G, 'HpmgDlHunt')
check(module ~= nil, 'module publishes its global state')
local internals = module and module.internals
check(internals ~= nil, 'module exposes internals')
if not internals then os.exit(1) end
local measure = internals.measure

print('measure: accepts a well-formed buffer')
do
    local buffer, total = make_buffer({128, 256, 64}, 0xBD4042C2)
    local measured, type_id, instances, mixed = measure(fake_api(buffer, total), buffer)
    equal(measured, total, 'measured total')
    equal(type_id, 0xBD4042C2, 'type id')
    equal(instances, 3, 'instance count')
    equal(mixed, false, 'single type')
end

print('measure: distinguishes random memory from a broken DL buffer')
do
    -- No magic: ordinary memory, not worth reporting.
    local buffer, total = make_buffer({64}, 0xBD4042C2, {magic = 0x41414141})
    local measured, reason, had_header = measure(fake_api(buffer, total), buffer)
    equal(measured, nil, 'rejected')
    equal(reason, 'no magic', 'reason')
    equal(had_header, false, 'NOT reported as a near miss')

    -- Magic present, version wrong: a real near miss.
    buffer, total = make_buffer({64}, 0xBD4042C2, {version = 9})
    measured, reason, had_header = measure(fake_api(buffer, total), buffer)
    equal(measured, nil, 'rejected')
    equal(had_header, true, 'reported as a near miss')
    check(tostring(reason):find('version') ~= nil, 'reason names the version')
end

print('measure: near-miss reasons stay specific')
do
    local cases = {
        {{wide = 0}, 'not 64%-bit'},
        {{reserved = 1}, 'reserved set'},
        {{count = 0}, 'zero instances'},
    }
    for _, case in ipairs(cases) do
        local buffer, total = make_buffer({64, 64}, 0xBD4042C2, case[1])
        local measured, reason, had_header = measure(fake_api(buffer, total), buffer)
        equal(measured, nil, 'rejects ' .. case[2])
        equal(had_header, true, case[2] .. ' counts as a near miss')
        check(tostring(reason):find(case[2]) ~= nil,
              string.format('reason %q names %q', tostring(reason), case[2]))
    end
end

print('measure: a truncated chain says where it stopped')
do
    -- Header claims 4 instances; only 2 are actually present.
    local buffer, total = make_buffer({64, 64}, 0xBD4042C2, {count = 4})
    local measured, reason, had_header = measure(fake_api(buffer, total), buffer)
    equal(measured, nil, 'rejected')
    equal(had_header, true, 'near miss')
    check(tostring(reason):find('instance 3/4') ~= nil,
          string.format('reason %q names the instance it failed on', tostring(reason)))
end

print('caps: raised past anything a settings file needs')
do
    -- generated_entities.dl_bin is the buffer the old 512 cap could have hidden.
    check(internals.max_instances >= 65536,
          string.format('instance cap is %d, needs to clear 65536', internals.max_instances))
    equal(internals.fingerprints[45630790], 'entities', 'entities fingerprint present')
    check(internals.dump_these.entities == true, 'entities is on the dump list')
    check(internals.dump_these.projectile_settings == true, 'projectile_settings still dumped')
    check(internals.dump_these.stratagem_settings == true,
          'stratagem_settings still dumped as the control')
end

print('caps: an over-cap buffer reports the count it saw')
do
    local buffer, total = make_buffer({64}, 0xBD4042C2, {count = internals.max_instances + 1})
    local measured, reason, had_header = measure(fake_api(buffer, total), buffer)
    equal(measured, nil, 'rejected')
    equal(had_header, true, 'near miss')
    check(tostring(reason):find('instance cap') ~= nil,
          string.format('reason %q names the cap', tostring(reason)))
    check(tostring(reason):find(tostring(internals.max_instances + 1)) ~= nil,
          'reason includes the count that was seen')
end

print('sweep: finds a buffer nothing points at')
do
    -- A synthetic "region" with a DL buffer buried in the middle of it, at an
    -- offset no pointer refers to. This is the case the globals scan cannot
    -- reach and the sweep exists for.
    local region_size = 300000
    local planted_at = 137000        -- deliberately not chunk-aligned
    local payloads = {400, 400}
    local buffer_total = 4
    for _, size in ipairs(payloads) do buffer_total = buffer_total + 24 + size end

    local memory = ffi.new('uint8_t[?]', region_size)
    ffi.cast('uint32_t *', memory + planted_at)[0] = #payloads
    local offset = planted_at + 4
    for _, size in ipairs(payloads) do
        local word = ffi.cast('uint32_t *', memory + offset)
        word[0] = MAGIC; word[1] = 1; word[2] = 0xABCD1234
        word[3] = size; word[4] = 1; word[5] = 0
        offset = offset + 24 + size
    end

    local scratch = ffi.new('uint8_t[?]', internals.chunk)
    local scratch32 = ffi.cast('uint32_t *', scratch)
    local header = ffi.new('uint8_t[64]')
    local header32 = ffi.cast('uint32_t *', header)
    local api = {}
    local function span(address)
        return tonumber(ffi.cast('intptr_t', address) - ffi.cast('intptr_t', memory))
    end
    function api.read_chunk(address, size)
        local at = span(address)
        if at < 0 or size > internals.chunk or at + size > region_size then return false end
        ffi.copy(scratch, memory + at, size)
        return true
    end
    function api.scan32() return scratch32 end
    function api.read_header(address, size)
        local at = span(address)
        if at < 0 or size > 64 or at + size > region_size then return false end
        ffi.copy(header, memory + at, size)
        return true
    end
    function api.header(index) return header32[index] end
    function api.regions() return {{base = ffi.cast('uint8_t *', memory), size = region_size}} end

    local probe = {found = {}, files = {}, rejects = {}, hits = 0, dumped = 0,
                   near_misses = 0, sweep_hits = 0}
    internals.reset_sweep(api)
    local guard = 0
    repeat
        guard = guard + 1
        local done = internals.sweep_memory(api, probe)
    until done or guard > 500
    check(guard <= 500, 'sweep terminates')
    equal(probe.sweep_hits, 1, 'found exactly the planted buffer')
    equal(probe.hits, 1, 'recorded one buffer')

    local key, text = next(probe.found)
    check(key ~= nil and tostring(key):find('heap') ~= nil,
          string.format('keyed as a heap find (got %s)', tostring(key)))
    check(tostring(text):find(tostring(buffer_total), 1, true) ~= nil,
          string.format('reports the right total (%d) in %q', buffer_total, tostring(text)))
    check(tostring(text):find('sweep', 1, true) ~= nil, 'records the sweep as its origin')
    check(tostring(text):find('ABCD1234') ~= nil, 'reports the type id')
end

print('sweep: does not re-report a buffer it already has')
do
    local probe = {found = {['heap 0x1'] = 'already known'}, files = {}, rejects = {},
                   hits = 0, dumped = 0, near_misses = 0, sweep_hits = 0}
    local added = internals.record_buffer(nil, probe, 'heap 0x1', nil, 100, 1, 1, false, 'sweep')
    equal(added, false, 'duplicate rejected')
    equal(probe.hits, 0, 'hit count untouched')
end

print('config: globals section still covers the known pointers')
do
    check(internals.globals.rva <= 0x2791F68
          and 0x2791F68 < internals.globals.rva + internals.globals.size,
          'stratagem pointer inside the scan range')
    check(0x02791848 < internals.globals.rva + internals.globals.size,
          'projectile pointer inside the scan range')
end

-- ---------------------------------------------------------------------------

print()
if failures == 0 then
    print(string.format('OK  %d checks passed', checks))
else
    print(string.format('FAILED  %d of %d checks', failures, checks))
    os.exit(1)
end
