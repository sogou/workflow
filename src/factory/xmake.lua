target("factory")
    add_files("*.cc")
    set_kind("object")
    if (get_config("mysql") == false) then
        remove_files("MySQLTaskImpl.cc")
    end
    if (get_config("redis") == false) then
        remove_files("RedisTaskImpl.cc")
    end
    remove_files("KafkaTaskImpl.cc")

target("kafka_factory")
    if (get_config("kafka") == true) then
        add_files("KafkaTaskImpl.cc")
        set_kind("object")
        add_cxxflags("-fno-rtti")
        add_deps("factory")
    else
        set_kind("phony")
    end
