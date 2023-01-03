target("nameservice")
    add_files("*.cc")
    set_kind("object")
    if not has_config("upstrem") then
        remove_files("WFServiceGovernance.cc", "UpstreamPolicies.cc")
    end

