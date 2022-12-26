includes("**/xmake.lua")

target("workflow")
    if (get_config("type") == "static") then
        set_kind("static")
    else
        set_kind("shared")
    end
    add_deps("algorithm", "client", "factory", "kernel", "manager",
             "nameservice", "protocol", "server", "util")

target("wfkafka")
    if (get_config("kafka") == true) then
        if (get_config("type") == "static") then
            set_kind("static")
        else
            set_kind("shared")
        end
        add_deps("kafka_client", "kafka_factory", "kafka_protocol", "kafka_util", "workflow")
    else
        set_kind("phony")
    end

on_load(function (package)
    local include_path = path.join(get_config("workflow_inc"), "workflow")
    if (not os.isdir(include_path)) then
    	os.mkdir(include_path)
    end

    os.cp(path.join("$(projectdir)", "src/**.h"), include_path)
    os.cp(path.join("$(projectdir)", "src/**.inl"), include_path)
end)

after_build(function (target)
    local lib_dir = get_config("workflow_lib")
    if (not os.isdir(lib_dir)) then
        os.mkdir(lib_dir)
    end
    if (get_config("type") == "static") then
        os.mv(path.join("$(projectdir)", target:targetdir(), "*.a"), lib_dir) 
    else
        os.mv(path.join("$(projectdir)", target:targetdir(), "*.so"), lib_dir)
    end
end)

after_clean(function (target)
    os.rm(get_config("workflow_inc"))
    os.rm(get_config("workflow_lib"))
    os.rm("$(buildir)")
end)

on_install(function (package)
    os.cp(path.join(get_config("workflow_inc"), "workflow"), path.join(package:installdir(), "include"))
    if (get_config("type") == "static") then
        os.cp(path.join(get_config("workflow_lib"), "*.a"), path.join(package:installdir(), "lib"))
    else
        os.cp(path.join(get_config("workflow_lib"), "*.so"), path.join(package:installdir(), "lib"))
    end
end)
