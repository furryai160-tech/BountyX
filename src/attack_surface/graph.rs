use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeType {
    Target,
    Host { fqdn: String, ip: Option<String> },
    Service { port: u16, proto: String, service_name: String },
    Endpoint { path: String, method: String },
    Parameter { name: String, param_type: String }, // query, body, header, path
    AuthBoundary { role: String, token_type: Option<String> },
    DataResource { resource_name: String, identifier_sample: Option<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EdgeType {
    ResolvesTo,
    ExposesService,
    RoutesTo,
    ConsumesParameter,
    RequiresAuth,
    AccessesResource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurfaceNode {
    pub id: String,
    pub label: String,
    pub node_type: NodeType,
    pub properties: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurfaceEdge {
    pub edge_type: EdgeType,
    pub weight: u32,
}

#[derive(Debug, Clone)]
pub struct AttackSurfaceGraph {
    graph: DiGraph<AttackSurfaceNode, AttackSurfaceEdge>,
    node_lookup: HashMap<String, NodeIndex>,
}

impl AttackSurfaceGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_lookup: HashMap::new(),
        }
    }

    pub fn add_or_get_node(&mut self, id: &str, label: &str, node_type: NodeType) -> NodeIndex {
        if let Some(&idx) = self.node_lookup.get(id) {
            return idx;
        }

        let node = AttackSurfaceNode {
            id: id.to_string(),
            label: label.to_string(),
            node_type,
            properties: HashMap::new(),
        };

        let idx = self.graph.add_node(node);
        self.node_lookup.insert(id.to_string(), idx);
        idx
    }

    pub fn add_edge(&mut self, from_id: &str, to_id: &str, edge_type: EdgeType) {
        if let (Some(&from_idx), Some(&to_idx)) = (self.node_lookup.get(from_id), self.node_lookup.get(to_id)) {
            // Avoid duplicate edges
            if !self.graph.contains_edge(from_idx, to_idx) {
                self.graph.add_edge(
                    from_idx,
                    to_idx,
                    AttackSurfaceEdge {
                        edge_type,
                        weight: 1,
                    },
                );
            }
        }
    }

    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    pub fn get_endpoints(&self) -> Vec<AttackSurfaceNode> {
        self.graph
            .node_weights()
            .filter(|n| matches!(n.node_type, NodeType::Endpoint { .. }))
            .cloned()
            .collect()
    }

    pub fn get_parameters_for_endpoint(&self, endpoint_id: &str) -> Vec<AttackSurfaceNode> {
        let mut params = Vec::new();
        if let Some(&idx) = self.node_lookup.get(endpoint_id) {
            for neighbor in self.graph.neighbors_directed(idx, Direction::Outgoing) {
                let node = &self.graph[neighbor];
                if matches!(node.node_type, NodeType::Parameter { .. }) {
                    params.push(node.clone());
                }
            }
        }
        params
    }

    pub fn get_auth_for_endpoint(&self, endpoint_id: &str) -> Option<AttackSurfaceNode> {
        if let Some(&idx) = self.node_lookup.get(endpoint_id) {
            for neighbor in self.graph.neighbors_directed(idx, Direction::Outgoing) {
                let node = &self.graph[neighbor];
                if matches!(node.node_type, NodeType::AuthBoundary { .. }) {
                    return Some(node.clone());
                }
            }
        }
        None
    }
}

impl Default for AttackSurfaceGraph {
    fn default() -> Self {
        Self::new()
    }
}
