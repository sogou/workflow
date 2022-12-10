target("bootstrap")
    set_kind("binary")
    add_files("bootstrap.c")

target("bootstrap_server")
    set_kind("binary")
    add_files("server.cc")
    add_deps("workflow")