set_group("tutorial")
set_default(false)

if not is_os("macosx") then
    add_ldflags("-lrt")
end

function all_examples()
    local res = {}
    for _, x in ipairs(os.files("*.cc")) do
        local item = {}
        local s = path.filename(x)
        if((s == "upstream_unittest.cc" and get_config("upstream") == false) or
           ((s == "tutorial-02-redis_cli.cc" or s == "tutorial-03-wget_to_redis.cc") and get_config("redis") == false) or
           (s == "tutorial-12-mysql_cli.cc" and get_config("mysql") == false) or
           (s == "tutorial-14-consul_cli.cc" and get_config("consul") == false) or
           (s == "tutorial-13-kafka_cli.cc")) then
        else
            table.insert(item, s:sub(1, #s - 3))       -- target
            table.insert(item, path.relative(x, "."))  -- source
            table.insert(res, item)
        end
    end
    return res
end

for _, example in ipairs(all_examples()) do
target(example[1])
    set_kind("binary")
    add_files(example[2])
    add_deps("workflow")
end

target("tutorial-13-kafka_cli")
    if (get_config("kafka") == true) then
        set_kind("binary")
        add_files("tutorial-13-kafka_cli.cc")
        add_packages("zlib", "snappy", "zstd", "lz4")
        add_deps("wfkafka")
    else
        set_kind("phony")
    end

includes("tutorial-10-user_defined_protocol", "tutorial-16-graceful_restart")
