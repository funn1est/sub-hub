use crate::node::ProxyNode;
use crate::node_name::{NamedNodeOccurrence, NamedSubscriptionSources};

mod golden;
mod limits;
mod mapping;
mod privacy;

/// Accepted nodes in occurrence order, borrowed from the naming result.
fn accepted_nodes(named: &NamedSubscriptionSources) -> Vec<&ProxyNode> {
    named
        .occurrences()
        .iter()
        .filter_map(|occurrence| match occurrence {
            NamedNodeOccurrence::Accepted { node, .. } => Some(node.as_ref()),
            NamedNodeOccurrence::Rejected { .. } => None,
        })
        .collect()
}
