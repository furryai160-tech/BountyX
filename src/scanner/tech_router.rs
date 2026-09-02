use std::collections::HashSet;

pub struct TechRouter;

impl TechRouter {
    /// Maps a list of detected technology strings (from HTTPX or HTTP headers)
    /// to an optimized set of Nuclei tags for surgical, context-aware scanning.
    pub fn resolve_nuclei_tags(technologies: &[String]) -> Vec<String> {
        let mut tags = HashSet::new();

        // Always include high-signal baseline tags for critical exposures
        tags.insert("cve".to_string());
        tags.insert("misconfig".to_string());
        tags.insert("exposure".to_string());
        tags.insert("token".to_string());

        for tech in technologies {
            let lower = tech.to_lowercase();

            // Java & Spring Framework
            if lower.contains("spring") || lower.contains("actuator") || lower.contains("java") {
                tags.insert("spring".to_string());
                tags.insert("springboot".to_string());
                tags.insert("actuator".to_string());
            }

            // GraphQL
            if lower.contains("graphql") || lower.contains("apollo") {
                tags.insert("graphql".to_string());
            }

            // PHP Frameworks
            if lower.contains("laravel") {
                tags.insert("laravel".to_string());
                tags.insert("ignition".to_string());
            }
            if lower.contains("wordpress") || lower.contains("wp") {
                tags.insert("wordpress".to_string());
                tags.insert("wp-plugin".to_string());
            }
            if lower.contains("drupal") {
                tags.insert("drupal".to_string());
            }
            if lower.contains("joomla") {
                tags.insert("joomla".to_string());
            }

            // API Docs & Gateways
            if lower.contains("swagger") || lower.contains("openapi") {
                tags.insert("swagger".to_string());
                tags.insert("openapi".to_string());
            }

            // CI/CD & DevOps tools
            if lower.contains("jenkins") {
                tags.insert("jenkins".to_string());
            }
            if lower.contains("gitlab") {
                tags.insert("gitlab".to_string());
            }
            if lower.contains("jira") || lower.contains("confluence") || lower.contains("atlassian") {
                tags.insert("jira".to_string());
                tags.insert("confluence".to_string());
                tags.insert("atlassian".to_string());
            }

            // Web Servers & Application Servers
            if lower.contains("tomcat") {
                tags.insert("tomcat".to_string());
            }
            if lower.contains("weblogic") {
                tags.insert("weblogic".to_string());
            }
            if lower.contains("nginx") {
                tags.insert("nginx".to_string());
            }
            if lower.contains("apache") {
                tags.insert("apache".to_string());
            }

            // Node.js & Modern JS Frameworks
            if lower.contains("next") || lower.contains("next.js") {
                tags.insert("nextjs".to_string());
            }
            if lower.contains("express") {
                tags.insert("express".to_string());
            }

            // Python Frameworks
            if lower.contains("django") {
                tags.insert("django".to_string());
            }
            if lower.contains("flask") {
                tags.insert("flask".to_string());
            }

            // Databases / Cache Expirations
            if lower.contains("kibana") || lower.contains("elasticsearch") {
                tags.insert("kibana".to_string());
                tags.insert("elasticsearch".to_string());
            }
            if lower.contains("redis") {
                tags.insert("redis".to_string());
            }
        }

        let mut sorted_tags: Vec<String> = tags.into_iter().collect();
        sorted_tags.sort();
        sorted_tags
    }

    /// Formats resolved tags as a comma-separated string for `-tags` CLI parameter
    pub fn format_tags_arg(technologies: &[String]) -> String {
        Self::resolve_nuclei_tags(technologies).join(",")
    }
}
