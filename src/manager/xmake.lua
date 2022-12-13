target("manager")
    add_files("*.cc")
    set_kind("object")
    if (get_config("upstrem") == false) then
        remove_files("UpstreamManager.cc")
    end