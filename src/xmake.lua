includes("**/xmake.lua")

on_install(function (target)
    os.cp(path.join(get_config("workflow_inc"), "workflow"), path.join(target:installdir(), "include"))
    if target:is_static() then
        os.cp(path.join(get_config("workflow_lib"), "*.a"), path.join(target:installdir(), "lib"))
    else
        os.cp(path.join(get_config("workflow_lib"), "*.so"), path.join(target:installdir(), "lib"))
    end
end)

after_build(function (target)
    local lib_dir = get_config("workflow_lib")
    if (not os.isdir(lib_dir)) then
        os.mkdir(lib_dir)
    end
    if target:is_static() then
        os.mv(path.join("$(projectdir)", target:targetdir(), "*.a"), lib_dir)
    else
        os.mv(path.join("$(projectdir)", target:targetdir(), "*.so"), lib_dir)
    end
end)

target("workflow")
    set_kind("$(kind)")
    add_deps("algorithm", "client", "factory", "kernel", "manager",
             "nameservice", "protocol", "server", "util")
    on_load(function (package)
        local include_path = path.join(get_config("workflow_inc"), "workflow")
        if (not os.isdir(include_path)) then
            os.mkdir(include_path)
        end

        os.cp(path.join("$(projectdir)", "src/**.h"), include_path)
        os.cp(path.join("$(projectdir)", "src/**.inl"), include_path)
    end)

target("wfkafka")
    if has_config("kafka") then
        set_kind("$(kind)")
        add_deps("kafka_client", "kafka_factory", "kafka_protocol", "kafka_util", "workflow")
    else
        set_kind("phony")
    end

