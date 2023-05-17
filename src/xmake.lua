includes("**/xmake.lua")

after_build(function (target)
    local lib_dir = get_config("workflow_lib")
    if (not os.isdir(lib_dir)) then
        os.mkdir(lib_dir)
    end
    shared_suffix = "*.so"
    if is_plat("macosx") then
        shared_suffix = "*.dylib"
    end
    if target:is_static() then
        os.mv(path.join("$(projectdir)", target:targetdir(), "*.a"), lib_dir)
    else
        os.mv(path.join("$(projectdir)", target:targetdir(), shared_suffix), lib_dir)
    end
end)

target("workflow")
    set_kind("$(kind)")
    add_deps("client", "factory", "kernel", "manager",
             "nameservice", "protocol", "server", "util")

    on_load(function (package)
        local include_path = path.join(get_config("workflow_inc"), "workflow")
        if (not os.isdir(include_path)) then
            os.mkdir(include_path)
        end

        os.cp(path.join("$(projectdir)", "src/include/**.h"), include_path)
        os.cp(path.join("$(projectdir)", "src/include/**.inl"), include_path)
    end)

    after_clean(function (target)
        os.rm(get_config("workflow_inc"))
        os.rm(get_config("workflow_lib"))
        os.rm("$(buildir)")
    end)

    on_install(function (target)
        os.mkdir(path.join(target:installdir(), "include/workflow"))
        os.mkdir(path.join(target:installdir(), "lib"))
        os.cp(path.join(get_config("workflow_inc"), "workflow"), path.join(target:installdir(), "include"))
        shared_suffix = "*.so"
        if is_plat("macosx") then
            shared_suffix = "*.dylib"
        end
        if target:is_static() then
            os.cp(path.join(get_config("workflow_lib"), "*.a"), path.join(target:installdir(), "lib"))
        else
            os.cp(path.join(get_config("workflow_lib"), shared_suffix), path.join(target:installdir(), "lib"))
        end
    end)

target("wfkafka")
    if has_config("kafka") then
        set_kind("$(kind)")
        add_deps("kafka_client", "kafka_factory", "kafka_protocol", "kafka_util", "workflow")
    else
        set_kind("phony")
    end

