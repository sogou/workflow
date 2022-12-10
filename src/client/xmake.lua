target("client")
    set_kind("object")
    add_files("*.cc")
    remove_files("WFKafkaClient.cc")
    if (get_config("mysql") == false) then
        remove_files("WFMySQLConnection.cc")
    end
    if (get_config("consul") == false) then
        remove_files("WFConsulClient.cc")
    end

target("kafka_client")
    if (get_config("kafka") == true) then
        add_files("WFKafkaClient.cc")
        set_kind("object")
        add_deps("client")
    else
        set_kind("phony")
    end
