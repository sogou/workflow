target("util")
    set_kind("object")
    add_files("*.c")
    add_files("*.cc")
    remove_files("crc32c.c")

target("kafka_util")
    if has_config("kafka") then
        set_kind("object")
        add_files("crc32c.c")
    else
        set_kind("phony")
    end
