//! Native edge-lb datapath facade.
//!
//! Native user-space datapath and proxy implementation.
//! It owns listener-to-datapath conversion and runtime state. Linux eBPF/TC
//! attachment stays in `linux`, and HTTP handlers should call this facade
//! instead of manipulating maps directly.

mod api_model;
pub mod flow_sync;
pub mod ha;
mod model;
pub mod probe;
mod store;
pub mod xsync;

#[allow(unused_imports)]
pub use api_model::{
    HealthProbeConfig, RuntimeRuleSpec, RuntimeRuleStateEntry, RuntimeRuleStateList,
    RuntimeRuleTarget, TargetHealthEntry, TargetHealthList,
};
#[allow(unused_imports)]
pub use model::{
    NativeListener, NativeListenerKey, NativeProtocol, NativeTarget, NativeTargetState,
    RuntimeRuleEntry, effective_vip_ips, listener_from_service, listeners_from_config,
};
#[allow(unused_imports)]
pub use probe::run_worker as run_probe_worker;
#[allow(unused_imports)]
pub use store::{
    create_or_update_listener, create_runtime_rule_state, default_external_ip, delete_listener,
    delete_runtime_rule, delete_target_group, desired_runtime_rules, ensure_runtime_rule,
    expanded_runtime_rule_entries, get_runtime_rules, hydrate_proxy_config_from_api,
    replace_runtime_rule_state_by_name, runtime_rules_native, take_state_dirty,
    target_groups_native, target_health, target_health_native, upsert_target_group,
};
