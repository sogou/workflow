target("factory")
    add_files("*.cc")
    set_kind("object")
    if not has_config("mysql") then
        remove_files("MySQLTaskImpl.cc")
    end
    if not has_config("redis") then
        remove_files("RedisTaskImpl.cc")
    end
    remove_files("KafkaTaskImpl.cc")

target("kafka_factory")
    if has_config("kafka") then
        add_files("KafkaTaskImpl.cc")
        set_kind("object")
        add_cxxflags("-fno-rtti")
        add_deps("factory")
        add_packages("zlib", "snappy", "zstd", "lz4")
    else
        set_kind("phony")
    end
