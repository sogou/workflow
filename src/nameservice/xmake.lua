target("nameservice")
    add_files("*.cc")
    set_kind("object")
    if (get_config("upstrem") == false) then
        remove_files("WFServiceGovernance.cc", "UpstreamPolicies.cc")
    end
    