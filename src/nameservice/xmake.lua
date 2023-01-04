target("nameservice")
    add_files("*.cc")
    set_kind("object")
    if not has_config("upstream") then
        remove_files("WFServiceGovernance.cc", "UpstreamPolicies.cc")
    end

