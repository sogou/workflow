target("manager")
    add_files("*.cc")
    set_kind("object")
    if not has_config("upstrem") then
        remove_files("UpstreamManager.cc")
    end
