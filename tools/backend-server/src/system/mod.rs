//! OS-specific interfaces used by the discovery engine.
//!
//! * [`ifaddr`] — network interface address enumeration (getifaddrs(3))
//! * [`route`] — default-route ("underlay device") detection

pub mod ifaddr;
pub mod route;
