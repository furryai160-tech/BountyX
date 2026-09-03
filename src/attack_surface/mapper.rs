use crate::attack_surface::graph::{AttackSurfaceGraph, EdgeType, NodeType};
use url::Url;

pub struct AttackSurfaceMapper;

impl AttackSurfaceMapper {
    pub fn ingest_url(graph: &mut AttackSurfaceGraph, target_domain: &str, raw_url: &str, method: &str) {
        if let Ok(parsed) = Url::parse(raw_url) {
            let host_str = parsed.host_str().unwrap_or(target_domain);
            let path_str = parsed.path();

            // 1. Ensure Host Node
            let host_id = format!("host:{}", host_str);
            graph.add_or_get_node(
                &host_id,
                host_str,
                NodeType::Host {
                    fqdn: host_str.to_string(),
                    ip: None,
                },
            );

            // 2. Ensure Endpoint Node
            let endpoint_id = format!("ep:{}:{}:{}", host_str, method, path_str);
            let ep_label = format!("{} {}", method, path_str);
            graph.add_or_get_node(
                &endpoint_id,
                &ep_label,
                NodeType::Endpoint {
                    path: path_str.to_string(),
                    method: method.to_uppercase(),
                },
            );

            // Connect Host -> Endpoint
            graph.add_edge(&host_id, &endpoint_id, EdgeType::RoutesTo);

            // 3. Extract and map Query Parameters
            for (param_name, param_val) in parsed.query_pairs() {
                let param_id = format!("param:{}:{}:{}", host_str, path_str, param_name);
                graph.add_or_get_node(
                    &param_id,
                    &param_name,
                    NodeType::Parameter {
                        name: param_name.to_string(),
                        param_type: "query".to_string(),
                    },
                );

                // Connect Endpoint -> Parameter
                graph.add_edge(&endpoint_id, &param_id, EdgeType::ConsumesParameter);

                // If parameter looks like an object identifier (e.g., id, user_id, account_id)
                let p_lower = param_name.to_lowercase();
                if p_lower.ends_with("_id") || p_lower == "id" || p_lower == "uuid" {
                    let res_id = format!("res:{}", param_name);
                    graph.add_or_get_node(
                        &res_id,
                        &format!("Resource ({})", param_name),
                        NodeType::DataResource {
                            resource_name: param_name.to_string(),
                            identifier_sample: Some(param_val.to_string()),
                        },
                    );
                    graph.add_edge(&endpoint_id, &res_id, EdgeType::AccessesResource);
                }
            }
        }
    }
}
