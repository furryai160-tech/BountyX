use bountyscope::scanner::tech_router::TechRouter;

#[test]
fn test_tech_router_spring_boot() {
    let techs = vec!["Spring Boot".to_string(), "Java".to_string()];
    let tags = TechRouter::resolve_nuclei_tags(&techs);

    assert!(tags.contains(&"spring".to_string()));
    assert!(tags.contains(&"springboot".to_string()));
    assert!(tags.contains(&"actuator".to_string()));
    assert!(tags.contains(&"cve".to_string()));
}

#[test]
fn test_tech_router_graphql_and_wordpress() {
    let techs = vec!["WordPress 6.2".to_string(), "GraphQL API".to_string()];
    let tags = TechRouter::resolve_nuclei_tags(&techs);

    assert!(tags.contains(&"wordpress".to_string()));
    assert!(tags.contains(&"wp-plugin".to_string()));
    assert!(tags.contains(&"graphql".to_string()));
}

#[test]
fn test_tech_router_format_args() {
    let techs = vec!["Laravel".to_string()];
    let formatted = TechRouter::format_tags_arg(&techs);

    assert!(formatted.contains("laravel"));
    assert!(formatted.contains("ignition"));
    assert!(formatted.contains("cve"));
}
