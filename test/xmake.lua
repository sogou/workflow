set_group("test")
set_default(false)

add_requires("gtest")

add_deps("workflow")

add_packages("gtest")
add_links("gtest_main")

if not is_plat("macosx") then
    add_ldflags("-lrt")
end

function all_tests()
    local res = {}
    for _, x in ipairs(os.files("**.cc")) do
        local item = {}
        local s = path.filename(x)
        if ((s == "upstream_unittest.cc" and not has_config("upstream")) or
            (s == "redis_unittest.cc" and not has_config("redis")) or
            (s == "mysql_unittest.cc" and not has_config("mysql"))) then
        else
            table.insert(item, s:sub(1, #s - 3)) -- target
            table.insert(item, path.relative(x, ".")) -- source
            table.insert(res, item)
        end
    end
    return res
end

for _, test in ipairs(all_tests()) do
    target(test[1])
    set_kind("binary")
    add_files(test[2])
    if has_config("memcheck") then
        on_run(function (target)
            local argv = {}
            table.insert(argv, target:targetfile())
            table.insert(argv, "--leak-check=full")
            os.execv("valgrind", argv)
        end)
    end
end
