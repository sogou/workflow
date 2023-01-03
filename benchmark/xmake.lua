set_group("benchmark")
set_default(false)

add_deps("workflow")

if not is_plat("macosx") then
    add_ldflags("-lrt")
end

function all_benchs()
    local res = {}
    for _, x in ipairs(os.files("**.cc")) do
        local item = {}
        local s = path.filename(x)
        table.insert(item, s:sub(1, #s - 3))       -- target
        table.insert(item, path.relative(x, "."))  -- source
        table.insert(res, item)
    end
    return res
end

for _, bench in ipairs(all_benchs()) do
target(bench[1])
    set_kind("binary")
    add_files(bench[2])
end
