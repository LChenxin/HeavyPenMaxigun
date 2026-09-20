-- Offline checks for mods/hpmg/heavy_pen_maxigun.lua.
--
-- This is the first module in the project that writes to process memory, so
-- the tests are about restraint rather than capability: that it refuses every
-- layout it does not recognise, that a successful write touches exactly twelve
-- bytes and leaves the rest of the buffer byte-identical, and that a failed
-- readback puts the original values back.

local ffi = require('ffi')

local DL_MAGIC = 0x444C444C
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

-- ---------------------------------------------------------------------------

assert(loadfile('mods/hpmg/heavy_pen_maxigun.lua'))()
local module = rawget(_G, 'HeavyPenMaxigun')
check(module ~= nil, 'module publishes its global state')
local internals = module and module.internals
check(internals ~= nil, 'module exposes internals')
if not internals then os.exit(1) end

local inspect, apply, TARGET, ANCHORS, BUFFER =
    internals.inspect, internals.apply, internals.target, internals.anchors, internals.buffer

-- Build a stand-in damage_settings buffer with the three records in place.
local function make_buffer(options)
    options = options or {}
    local memory = ffi.new('uint8_t[?]', BUFFER.size)
    local words = ffi.cast('uint32_t *', memory)
    words[0] = options.instances or BUFFER.instances
    words[1] = options.magic or DL_MAGIC
    words[2] = options.version or 1
    words[3] = options.type_id or BUFFER.type_id
    words[4] = BUFFER.size - 28
    words[5] = 1
    words[6] = 0

    local function put(offset, values)
        local lane = ffi.cast('uint32_t *', memory + offset)
        for index, value in ipairs(values) do lane[index - 1] = value end
    end
    put(TARGET.offset, options.target or TARGET.vanilla)
    for index, anchor in ipairs(ANCHORS) do
        local values = anchor.values
        if options.break_anchor == index then
            values = {}
            for i, v in ipairs(anchor.values) do values[i] = v end
            values[4] = values[4] + 7
        end
        put(anchor.offset, values)
    end
    return memory
end

local function snapshot(memory)
    return ffi.string(memory, BUFFER.size)
end

local function fake_api(memory, options)
    options = options or {}
    local scratch = ffi.new('uint8_t[256]')
    local words = ffi.cast('uint32_t *', scratch)
    local api = {writes = 0, written_bytes = 0, write_addresses = {}}
    local function span(address)
        return tonumber(ffi.cast('intptr_t', address) - ffi.cast('intptr_t', memory))
    end
    function api.read(address, size)
        local at = span(address)
        if at < 0 or size < 1 or size > 256 or at + size > BUFFER.size then return false end
        ffi.copy(scratch, memory + at, size)
        return true
    end
    function api.word(index) return words[index] end
    function api.pointer_at() return ffi.cast('uint8_t *', memory) end
    function api.writable_data() return not options.refuse_writes end
    function api.write_words(address, values)
        if options.refuse_writes then return false, 'not writable private data' end
        local at = span(address)
        if at < 0 or at + #values * 4 > BUFFER.size then return false, 'out of range' end
        api.writes = api.writes + 1
        api.written_bytes = api.written_bytes + #values * 4
        api.write_addresses[#api.write_addresses + 1] = at
        local lane = ffi.cast('uint32_t *', memory + at)
        for index, value in ipairs(values) do lane[index - 1] = value end
        if options.corrupt_on_write then
            -- Simulate the write landing wrong, so the readback must fail.
            ffi.cast('uint32_t *', memory + TARGET.offset)[1] = 999
        end
        return true
    end
    return api
end

-- ---------------------------------------------------------------------------

print('inspect: recognises the vanilla record')
do
    local memory = make_buffer()
    local condition, reason = inspect(fake_api(memory), ffi.cast('uint8_t *', memory))
    equal(condition, 'vanilla', 'vanilla detected (' .. tostring(reason) .. ')')
end

print('inspect: recognises an already-patched record')
do
    local memory = make_buffer({target = TARGET.patched})
    local condition = inspect(fake_api(memory), ffi.cast('uint8_t *', memory))
    equal(condition, 'patched', 'patched detected')
end

print('inspect: refuses a buffer that is not damage_settings')
do
    local cases = {
        {{instances = 5}, 'instance count'},
        {{magic = 0x41414141}, 'no DL magic'},
        {{version = 3}, 'DL version'},
        {{type_id = 0xDEADBEEF}, 'type'},
    }
    for _, case in ipairs(cases) do
        local memory = make_buffer(case[1])
        local condition, reason = inspect(fake_api(memory), ffi.cast('uint8_t *', memory))
        equal(condition, nil, 'refuses ' .. case[2])
        check(tostring(reason):find(case[2], 1, true) ~= nil,
              string.format('reason %q names %q', tostring(reason), case[2]))
    end
end

print('inspect: refuses when a published anchor disagrees')
do
    for index, anchor in ipairs(ANCHORS) do
        local memory = make_buffer({break_anchor = index})
        local condition, reason = inspect(fake_api(memory), ffi.cast('uint8_t *', memory))
        equal(condition, nil, 'refuses a moved layout via ' .. anchor.name)
        check(tostring(reason):find(anchor.name, 1, true) ~= nil,
              string.format('reason names %s', anchor.name))
    end
end

print('inspect: refuses an unrecognised target record')
do
    local altered = {}
    for index, value in ipairs(TARGET.vanilla) do altered[index] = value end
    altered[2] = 81                      -- damage 80 -> 81: not ours to touch
    local memory = make_buffer({target = altered})
    local condition, reason = inspect(fake_api(memory), ffi.cast('uint8_t *', memory))
    equal(condition, nil, 'refuses an unexpected target record')
    check(tostring(reason):find('target', 1, true) ~= nil, 'reason names the target')
end

print('apply: touches only the fields the plan names')
do
    local memory = make_buffer()
    local before = snapshot(memory)
    local api = fake_api(memory)
    local outcome = apply(api, ffi.cast('uint8_t *', memory))
    equal(outcome, 'applied', 'reports applied')

    -- Derived from the plan rather than hardcoded, so switching TEST_DAMAGE on
    -- or off cannot leave this test asserting a stale byte count.
    local planned_bytes, planned = 0, {}
    for _, step in ipairs(internals.plan) do
        planned_bytes = planned_bytes + #step.after * 4
        for byte = 0, #step.after * 4 - 1 do planned[step.offset + byte] = true end
    end
    equal(api.writes, #internals.plan, 'one write call per planned field')
    equal(api.written_bytes, planned_bytes, 'wrote exactly the planned byte count')
    for index, step in ipairs(internals.plan) do
        equal(api.write_addresses[index], TARGET.offset + step.offset,
              'write ' .. index .. ' landed on ' .. step.label)
    end

    local after = snapshot(memory)
    equal(#before, #after, 'buffer size unchanged')
    local outside = 0
    for index = 1, #before do
        if before:byte(index) ~= after:byte(index) then
            local within = (index - 1) - TARGET.offset
            if not planned[within] then outside = outside + 1 end
        end
    end
    equal(outside, 0, 'no byte outside the planned fields changed')

    local lane = ffi.cast('uint32_t *', memory + TARGET.offset)
    for index = 1, internals.pen_count do
        equal(lane[2 + index], internals.pen_value,
              string.format('penetration slot %d is %d', index, internals.pen_value))
    end
    equal(lane[6], 0, 'extreme-angle slot left at 0')
    equal(lane[0], TARGET.vanilla[1], 'id untouched')
    equal(lane[2], TARGET.vanilla[3], 'durable damage untouched')
    equal(lane[7], TARGET.vanilla[8], 'demolition untouched')
    equal(lane[8], TARGET.vanilla[9], 'stagger untouched')
    equal(lane[9], TARGET.vanilla[10], 'push untouched')

    if internals.test_damage then
        equal(lane[1], internals.test_damage, 'TEST damage applied')
        equal(TARGET.patched[2], internals.test_damage, 'expected record carries the test damage')
    else
        equal(lane[1], TARGET.vanilla[2], 'damage untouched when TEST_DAMAGE is off')
    end
end

print('apply: the plan always includes penetration and never the extreme angle')
do
    local saw_penetration = false
    for _, step in ipairs(internals.plan) do
        if step.offset == internals.pen_offset then
            saw_penetration = true
            equal(#step.after, internals.pen_count, 'penetration writes three dwords')
            for _, value in ipairs(step.after) do
                equal(value, internals.pen_value, 'penetration value')
            end
        end
        check(step.offset + #step.after * 4 <= internals.pen_offset + internals.pen_count * 4
              or step.offset >= internals.pen_offset + internals.pen_count * 4
              or step.offset == internals.pen_offset,
              step.label .. ' does not straddle the penetration field')
        equal(#step.before, #step.after, step.label .. ' records a rollback value per written dword')
    end
    check(saw_penetration, 'penetration is always part of the plan')
    -- +0x18 is the extreme-angle slot; nothing may write into it.
    for _, step in ipairs(internals.plan) do
        check(not (step.offset <= 0x18 and 0x18 < step.offset + #step.after * 4),
              step.label .. ' leaves the extreme-angle slot alone')
    end
end

print('apply: is idempotent')
do
    local memory = make_buffer({target = TARGET.patched})
    local api = fake_api(memory)
    local outcome = apply(api, ffi.cast('uint8_t *', memory))
    equal(outcome, 'already', 'reports already applied')
    equal(api.writes, 0, 'nothing written the second time')
end

print('apply: refuses when the pages are not writable private data')
do
    local memory = make_buffer()
    local before = snapshot(memory)
    local api = fake_api(memory, {refuse_writes = true})
    local outcome, reason = apply(api, ffi.cast('uint8_t *', memory))
    equal(outcome, nil, 'refused')
    check(tostring(reason):find('write refused', 1, true) ~= nil, 'reason says the write was refused')
    equal(snapshot(memory), before, 'buffer untouched')
end

print('apply: rolls back when the readback disagrees')
do
    local memory = make_buffer()
    local before = snapshot(memory)
    local api = fake_api(memory, {corrupt_on_write = true})
    local outcome, reason = apply(api, ffi.cast('uint8_t *', memory))
    equal(outcome, nil, 'refused after readback')
    check(tostring(reason):find('readback', 1, true) ~= nil, 'reason names the readback')
    check(tostring(reason):find('rollback=true', 1, true) ~= nil, 'rollback reported as done')
    local lane = ffi.cast('uint32_t *', memory + TARGET.offset)
    for index = 1, internals.pen_count do
        equal(lane[2 + index], TARGET.vanilla[3 + index],
              string.format('penetration slot %d restored', index))
    end
end

print('real Windows API: the layer the synthetic tests stub out')
do
    -- Everything above hands apply() a fake api, which is why a crash inside
    -- the real writable_data() -- arithmetic on a void * that LuaJIT refuses --
    -- reached the game untested. These checks drive the actual FFI layer
    -- against this process's own memory.
    local built, api = pcall(internals.create_api)
    check(built, 'create_api succeeds (' .. tostring(api) .. ')')
    if built then
        local scratch = ffi.new('uint32_t[8]')
        for index = 0, 7 do scratch[index] = 0x11110000 + index end
        local address = ffi.cast('uint8_t *', scratch)

        local ok, verdict = pcall(api.writable_data, address, 12)
        check(ok, 'writable_data does not throw (' .. tostring(verdict) .. ')')
        equal(verdict, true, 'a private read/write buffer is accepted')

        ok, verdict = pcall(api.writable_data, address, 0)
        check(ok and verdict == false, 'a zero-length request is refused')

        -- A mapped module image is MEM_IMAGE, never MEM_PRIVATE: the guard that
        -- keeps this mod away from executable and module memory.
        local module = api.module(nil)
        check(module ~= nil, 'can resolve this process module')
        if module then
            ok, verdict = pcall(api.writable_data, module, 12)
            check(ok, 'writable_data survives a module address')
            equal(verdict, false, 'mapped module memory is refused')
        end

        ok, verdict = pcall(api.read, address, 32)
        check(ok and verdict == true, 'read of real memory succeeds')
        if ok and verdict then
            equal(api.word(0), 0x11110000, 'first dword read back')
            equal(api.word(3), 0x11110003, 'fourth dword read back')
        end

        local wrote, problem = api.write_words(address + 12, {4, 4, 4})
        check(wrote, 'write_words succeeds on real memory (' .. tostring(problem) .. ')')
        equal(scratch[3], 4, 'dword 3 written')
        equal(scratch[4], 4, 'dword 4 written')
        equal(scratch[5], 4, 'dword 5 written')
        equal(scratch[2], 0x11110002, 'the dword before the run is untouched')
        equal(scratch[6], 0x11110006, 'the dword after the run is untouched')

        -- Refusing to write into a module is the property that matters most.
        if module then
            local refused = api.write_words(module, {0})
            equal(refused, false, 'writing into module memory is refused')
        end
    end
end

print('config: the constants match the analysis')
do
    equal(BUFFER.rva, 0x02791748, 'damage_settings pointer RVA')
    equal(BUFFER.size, 48664, 'decrypted buffer size')
    equal(BUFFER.type_id, 0xEB1433DA, 'root type id')
    equal(TARGET.offset, 0x02664, 'Maxigun record offset')
    equal(TARGET.vanilla[1], 123, 'damage-info id')
    equal(TARGET.vanilla[2], 80, 'damage matches the published stat')
    equal(TARGET.vanilla[3], 18, 'durable damage matches the published stat')
    equal(internals.pen_value, 4, 'target penetration equals the HMG/AMR tier')
    for _, anchor in ipairs(ANCHORS) do
        equal(anchor.values[4], 4, anchor.name .. ' anchor is the 4-tier we are copying')
        equal(anchor.values[7], 0, anchor.name .. ' anchor extreme angle is 0')
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
