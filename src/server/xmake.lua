target("server")
    set_kind("object")
    add_files("*.cc")
    if not has_config("mysql") then
        remove_files("WFMySQLServer.cc")
    end
