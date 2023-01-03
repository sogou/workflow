target("client")
    set_kind("object")
    add_files("*.cc")
    remove_files("WFKafkaClient.cc")
    if not has_config("mysql") then
        remove_files("WFMySQLConnection.cc")
    end
    if not has_config("consul") then
        remove_files("WFConsulClient.cc")
    end

target("kafka_client")
    if has_config("kafka") then
        add_files("WFKafkaClient.cc")
        set_kind("object")
        add_deps("client")
        add_packages("zlib", "snappy", "zstd", "lz4")
    else
        set_kind("phony")
    end
