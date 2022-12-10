target("server")
    set_kind("object")
    add_files("*.cc")
    if (get_config("mysql") == false) then
        remove_files("WFMySQLServer.cc")
    end