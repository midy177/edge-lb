use std::net::{IpAddr, Ipv4Addr};

use anyhow::Result;

use super::{
    model::{
        AutomationTemplate, FilterField, FilterOp, MatchedNode, NodeFilter, NodeScope,
        PlannedTargetGroup,
    },
    validate::{generated_target_group_name, ipv4_in_cidr},
};

pub fn matched_nodes(template: &AutomationTemplate, nodes: &[MatchedNode]) -> Vec<MatchedNode> {
    if matches!(template.node_scope, NodeScope::All) {
        return nodes.to_vec();
    }
    let Some(filter) = template.node_filter.as_ref() else {
        return nodes.to_vec();
    };
    nodes
        .iter()
        .filter(|node| matches_node(node, filter).unwrap_or(false))
        .cloned()
        .collect()
}

pub fn plan_template(template: &AutomationTemplate, nodes: &[MatchedNode]) -> PlannedTargetGroup {
    let targets = matched_nodes(template, nodes);
    let probe_type = template
        .target_group
        .probe_type
        .as_deref()
        .unwrap_or("none")
        .to_string();
    PlannedTargetGroup {
        template: template.name.clone(),
        name: generated_target_group_name(template),
        monitor: template.target_group.monitor,
        probe_type,
        targets,
    }
}

fn matches_node(node: &MatchedNode, filter: &NodeFilter) -> Result<bool> {
    for condition in &filter.conditions {
        let current = field_value(node, condition.field);
        let want = condition.value.trim();
        let matched = match condition.op {
            FilterOp::Equals => current == want,
            FilterOp::NotEquals => current != want,
            FilterOp::Prefix => current.starts_with(want),
            FilterOp::NotPrefix => !current.starts_with(want),
            FilterOp::Contains => current.contains(want),
            FilterOp::NotContains => !current.contains(want),
            FilterOp::Regex => regex::Regex::new(want)?.is_match(&current),
            FilterOp::InCidr => match current.parse::<IpAddr>()? {
                IpAddr::V4(ip) => ipv4_in_cidr(ip, want)?,
                IpAddr::V6(_) => false,
            },
            FilterOp::NotInCidr => match current.parse::<IpAddr>() {
                Ok(IpAddr::V4(ip)) => !ipv4_in_cidr(ip, want)?,
                Ok(IpAddr::V6(_)) | Err(_) => true,
            },
        };
        if !matched {
            return Ok(false);
        }
    }
    Ok(true)
}

fn field_value(node: &MatchedNode, field: FilterField) -> String {
    match field {
        FilterField::Name => node.name.clone(),
        FilterField::UnderlayIp => node.underlay_ip.clone(),
        FilterField::PublicIp => node.public_ip.clone(),
        FilterField::UnderlayIpSource => node.underlay_ip_source.clone().unwrap_or_default(),
        FilterField::PublicIpSource => node.public_ip_source.clone().unwrap_or_default(),
    }
}

pub fn matched_node_from_backend(
    name: String,
    public_ip: IpAddr,
    underlay_ip: IpAddr,
    public_ip_source: Option<String>,
    underlay_ip_source: Option<String>,
) -> Option<MatchedNode> {
    let IpAddr::V4(underlay) = underlay_ip else {
        return None;
    };
    if underlay == Ipv4Addr::UNSPECIFIED {
        return None;
    }
    Some(MatchedNode {
        name,
        underlay_ip: underlay.to_string(),
        public_ip: match public_ip {
            IpAddr::V4(ip) if ip != Ipv4Addr::UNSPECIFIED => ip.to_string(),
            IpAddr::V6(ip) if !ip.is_unspecified() => ip.to_string(),
            _ => "auto".to_string(),
        },
        underlay_ip_source,
        public_ip_source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::automation::model::{
        AutomationTemplate, FilterCondition, NodeFilter, TargetGroupTemplate,
    };

    fn node(name: &str, underlay_ip: &str) -> MatchedNode {
        MatchedNode {
            name: name.to_string(),
            underlay_ip: underlay_ip.to_string(),
            public_ip: "auto".to_string(),
            underlay_ip_source: Some("udp_source".to_string()),
            public_ip_source: Some("stun".to_string()),
        }
    }

    #[test]
    fn plan_template_creates_one_target_group_with_matched_targets() {
        let template = AutomationTemplate {
            name: "template-targets-a".to_string(),
            node_scope: NodeScope::Filtered,
            node_filter: Some(NodeFilter {
                conditions: vec![FilterCondition {
                    field: FilterField::Name,
                    op: FilterOp::Prefix,
                    value: "backend-".to_string(),
                }],
                ..NodeFilter::default()
            }),
            target_group: TargetGroupTemplate {
                name: "targets-a".to_string(),
                monitor: true,
                probe_type: Some("http".to_string()),
                ..TargetGroupTemplate::default()
            },
            ..AutomationTemplate::default()
        };

        let planned = plan_template(
            &template,
            &[
                node("backend-a", "192.168.0.14"),
                node("other", "192.168.0.15"),
            ],
        );

        assert_eq!(planned.name, "targets-a");
        assert_eq!(planned.template, "template-targets-a");
        assert!(planned.monitor);
        assert_eq!(planned.probe_type, "http");
        assert_eq!(planned.targets.len(), 1);
        assert_eq!(planned.targets[0].underlay_ip, "192.168.0.14");
    }

    #[test]
    fn negative_filter_ops_work() {
        let template = AutomationTemplate {
            node_scope: NodeScope::Filtered,
            node_filter: Some(NodeFilter {
                conditions: vec![
                    FilterCondition {
                        field: FilterField::Name,
                        op: FilterOp::NotPrefix,
                        value: "skip-".to_string(),
                    },
                    FilterCondition {
                        field: FilterField::UnderlayIp,
                        op: FilterOp::NotInCidr,
                        value: "192.168.1.0/24".to_string(),
                    },
                ],
                ..NodeFilter::default()
            }),
            ..AutomationTemplate::default()
        };

        let matched = matched_nodes(
            &template,
            &[
                node("backend-a", "192.168.0.14"),
                node("skip-a", "192.168.0.15"),
                node("backend-b", "192.168.1.14"),
            ],
        );

        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].name, "backend-a");
    }
}
