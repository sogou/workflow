add_deps("workflow")

target("user_defined_message")
    set_kind("object")
    add_files("message.cc")

target("user_defined_server")
    set_kind("binary")
    add_files("server.cc")
    add_deps("user_defined_message")

target("server-uds")
    set_kind("binary")
    add_files("server-uds.cc")
    add_deps("user_defined_message")

target("user_defined_client")
    set_kind("binary")
    add_files("client.cc")
    add_deps("user_defined_message")

target("client-uds")
    set_kind("binary")
    add_files("client-uds.cc")
    add_deps("user_defined_message")
