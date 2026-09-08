//! Native edge-lb datapath facade.
//!
//! Native user-space datapath and proxy implementation.
//! It owns listener-to-datapath conversion and runtime state. Linux eBPF/TC
//! attachment stays in `linux`, and HTTP handlers should call this facade
//! instead of manipulating maps directly.

mod api_model;
pub mod ha;
mod model;
pub mod probe;
mod store;
pub mod xsync;

#[allow(unused_imports)]
pub use api_model::{
    HealthProbeConfig, NativeListenerSpec, NativeListenerStateEntry, NativeListenerStateList,
    NativeListenerTarget, TargetHealthEntry, TargetHealthList,
};
#[allow(unused_imports)]
pub use model::{
    NativeListener, NativeListenerKey, NativeProtocol, NativeTarget, NativeTargetState,
    effective_vip_ips, listeners_from_config,
};
#[allow(unused_imports)]
pub use probe::run_worker as run_probe_worker;
#[allow(unused_imports)]
pub use store::{
    create_or_update_listener, default_external_ip, delete_listener, delete_target_group,
    hydrate_proxy_config_from_api, native_listeners_state, take_state_dirty, target_groups_native,
    target_health, target_health_native, upsert_target_group,
};
