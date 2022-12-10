target("kernel")
    set_kind("object")
    add_files("*.cc")
    add_files("*.c")
    if is_plat("linux", "android") then
        remove_files("IOService_thread.cc")
    else
    	remove_files("IOService_linux.cc")
    end
