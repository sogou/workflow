set_project("workflow")
set_languages("c90", "c++11")
set_version("0.10.5")

if is_mode("debug") then
    set_symbols("debug")
    set_optimize("none")
end

if is_mode("release") then
    set_symbols("hidden")
    set_optimize("fastest")
    set_strip("all")
end

option("workflow_inc")
    set_default("$(projectdir)/_include")
    set_showmenu(true)
    set_description("workflow inc")
option_end()

option("workflow_lib")
    set_default("$(projectdir)/_lib")
    set_showmenu(true)
    set_description("workflow lib")
option_end()

option("kafka")
    set_default(false)
    set_showmenu(true)
    set_description("build kafka component")
option_end()

option("consul")
    set_default(true)
    set_showmenu(true)
    set_description("build consul component")
option_end()

option("mysql")
    set_default(true)
    set_showmenu(true)
    set_description("build mysql component")
option_end()

option("redis")
    set_default(true)
    set_showmenu(true)
    set_description("build redis component")
option_end()

option("upstream")
    set_default(true)
    set_showmenu(true)
    set_description("build upstream component")
option_end()

option("type")
    set_default("static")
    set_showmenu(true)
    set_description("build lib static/shared")
option_end()

add_requires("openssl")
add_packages("openssl", {links = "ssl", "crypto"})
add_syslinks("pthread")

if (get_config("kafka") == true) then
    add_requires("snappy", "lz4", "zstd", "zlib")
end

add_includedirs(get_config("workflow_inc"))
add_includedirs(path.join(get_config("workflow_inc"), "workflow"))

set_config("buildir", "build.xmake")

add_cflags("-Wall -fPIC -pipe")
add_cxxflags("-Wall -fPIC -pipe -fno-exceptions -Wno-invalid-offsetof")

includes("src", "test", "benchmark", "tutorial")

