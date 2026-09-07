#![no_std]

#[cfg(feature = "user")]
extern crate std;

/// Maximum number of destination ports the DSCP marker can match.
pub const MAX_PORTS: usize = 16;
/// Default DSCP value. 46 is Expedited Forwarding (tos 0xb8).
pub const DEFAULT_DSCP: u32 = 46;
/// Default marked port: the VIP port exposed on the gateway.
pub const DEFAULT_PORT: u32 = 48080;
/// Default source-IP persistence lifetime for `persist` selection.
pub const DEFAULT_PERSIST_TIMEOUT_SECS: u32 = 3 * 60 * 60;
pub const NATIVE_SELECT_RR: u32 = 0;
pub const NATIVE_SELECT_HASH: u32 = 1;
pub const NATIVE_SELECT_PRIORITY: u32 = 2;
pub const NATIVE_SELECT_PERSIST: u32 = 3;
pub const NATIVE_SELECT_LC: u32 = 4;

/// Name of the TC classifier program inside the eBPF object.
pub const PROGRAM_NAME: &str = "dscp_mark";

/// Hard cap on endpoints per native service. Native eBPF selectors iterate a
/// compile-time bound so the verifier sees bounded loops; user space clamps
/// endpoint map writes to the same limit.
pub const MAX_ENDPOINTS_PER_SERVICE: u32 = 64;
pub const NATIVE_DNAT_INGRESS_PROGRAM: &str = "native_dnat_ingress";
pub const NATIVE_DNAT_RETURN_PROGRAM: &str = "native_dnat_return";

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Stats {
    pub matched: u64,
    pub changed: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Stats {}

/// IPv4 listener lookup key for the native DNAT datapath.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NativeServiceKey {
    /// IPv4 VIP in network byte order.
    pub vip: u32,
    /// TCP/UDP destination port in network byte order.
    pub port: u16,
    /// IP protocol number: TCP=6, UDP=17.
    pub proto: u8,
    pub _pad: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NativeServiceValue {
    pub service_id: u32,
    pub endpoint_base: u32,
    pub endpoint_count: u32,
    pub weight_total: u32,
    pub select: u32,
    pub flags: u32,
    pub timeout_secs: u32,
    pub dscp: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NativeEndpointKey {
    pub service_id: u32,
    pub endpoint_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NativeEndpointValue {
    /// IPv4 backend address in network byte order.
    pub address: u32,
    /// TCP/UDP backend target port in host byte order.
    pub port: u16,
    pub weight: u16,
    pub flags: u32,
}

/// Per-service/backend key used by the least-connections scheduler.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NativeEndpointLoadKey {
    pub service_id: u32,
    pub endpoint_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NativeFlowKey {
    pub src: u32,
    pub dst: u32,
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NativeFlowValue {
    pub service_id: u32,
    pub endpoint_id: u32,
    pub vip: u32,
    pub endpoint: u32,
    pub vip_port: u16,
    pub endpoint_port: u16,
    /// Idle timeout copied from the listener when the flow is created.
    pub timeout_secs: u32,
    pub last_seen_ns: u64,
}

#[cfg(test)]
mod scheduler_tests {
    use super::{
        NATIVE_SELECT_HASH, NATIVE_SELECT_LC, NATIVE_SELECT_PERSIST, NATIVE_SELECT_PRIORITY,
        NATIVE_SELECT_RR, NativeFlowKey,
    };

    fn key(source_port: u16) -> NativeFlowKey {
        NativeFlowKey {
            src: 0x0102_0304,
            dst: 0x0506_0708,
            sport: source_port.to_be(),
            dport: 9999_u16.to_be(),
            proto: 6,
            _pad: [0; 3],
        }
    }

    fn weighted_pick(seed: u32, weights: &[u16], active: &[bool]) -> Option<usize> {
        let total = weights
            .iter()
            .zip(active)
            .filter_map(|(weight, enabled)| enabled.then_some(u32::from(*weight)))
            .sum::<u32>();
        if total == 0 {
            return None;
        }
        let mut cursor = seed % total;
        for (index, (weight, enabled)) in weights.iter().zip(active).enumerate() {
            if *enabled && *weight > 0 {
                if cursor < u32::from(*weight) {
                    return Some(index);
                }
                cursor -= u32::from(*weight);
            }
        }
        None
    }

    fn slot_pick(seed: u32, weights: &[u16], active: &[bool]) -> Option<usize> {
        if active.is_empty() {
            return None;
        }
        let primary = seed as usize % active.len();
        if active[primary] && weights[primary] > 0 {
            return Some(primary);
        }
        active
            .iter()
            .zip(weights)
            .position(|(enabled, weight)| *enabled && *weight > 0)
    }

    fn persist_pick(client_ip: u32, weights: &[u16], active: &[bool]) -> Option<usize> {
        if active.is_empty() {
            return None;
        }
        let primary = ((client_ip & 0xff) ^ ((client_ip >> 24) & 0xff)) as usize % active.len();
        if active[primary] && weights[primary] > 0 {
            return Some(primary);
        }
        let secondary =
            (((client_ip >> 8) & 0xff) ^ ((client_ip >> 16) & 0xff)) as usize % active.len();
        if active[secondary] && weights[secondary] > 0 {
            return Some(secondary);
        }
        active
            .iter()
            .zip(weights)
            .position(|(enabled, weight)| *enabled && *weight > 0)
    }

    fn rr_pick(cursor: u32, weights: &[u16], active: &[bool]) -> Option<usize> {
        if active.is_empty() {
            return None;
        }
        for offset in 0..active.len() {
            let index = (cursor as usize + offset) % active.len();
            if active[index] && weights[index] > 0 {
                return Some(index);
            }
        }
        None
    }

    #[test]
    fn weighted_selection_skips_unhealthy_targets() {
        assert_eq!(weighted_pick(0, &[1, 1], &[false, true]), Some(1));
        assert_eq!(weighted_pick(10, &[1, 1], &[false, false]), None);
    }

    #[test]
    fn weighted_selection_respects_weight_ranges() {
        assert_eq!(weighted_pick(0, &[2, 1], &[true, true]), Some(0));
        assert_eq!(weighted_pick(1, &[2, 1], &[true, true]), Some(0));
        assert_eq!(weighted_pick(2, &[2, 1], &[true, true]), Some(1));
    }

    #[test]
    fn hash_selection_uses_endpoint_slots_without_weight_expansion() {
        assert_eq!(slot_pick(0, &[3, 1], &[true, true]), Some(0));
        assert_eq!(slot_pick(1, &[3, 1], &[true, true]), Some(1));
        assert_eq!(slot_pick(2, &[3, 1], &[true, true]), Some(0));
    }

    #[test]
    fn hash_selection_falls_back_to_first_healthy_slot() {
        assert_eq!(slot_pick(0, &[1, 1], &[false, true]), Some(1));
        assert_eq!(slot_pick(0, &[1, 1], &[false, false]), None);
    }

    #[test]
    fn rr_selection_rotates_slots_without_weight_expansion() {
        assert_eq!(rr_pick(0, &[3, 1], &[true, true]), Some(0));
        assert_eq!(rr_pick(1, &[3, 1], &[true, true]), Some(1));
        assert_eq!(rr_pick(2, &[3, 1], &[true, true]), Some(0));
    }

    #[test]
    fn persist_seed_ignores_client_transport_port() {
        let first = key(40000);
        let second = key(40001);
        assert_eq!(first.src, second.src);
        assert_eq!(
            persist_pick(first.src, &[1, 1], &[true, true]),
            persist_pick(second.src, &[1, 1], &[true, true])
        );
    }

    #[test]
    fn persist_selection_uses_source_ip_slots_without_weight_expansion() {
        assert_eq!(persist_pick(0x0102_0304, &[3, 1], &[true, true]), Some(1));
    }

    #[test]
    fn persist_default_timeout_is_three_hours() {
        assert_eq!(super::DEFAULT_PERSIST_TIMEOUT_SECS, 10_800);
    }

    #[test]
    fn selector_codes_match_native_datapath_contract() {
        assert_eq!(NATIVE_SELECT_RR, 0);
        assert_eq!(NATIVE_SELECT_HASH, 1);
        assert_eq!(NATIVE_SELECT_PRIORITY, 2);
        assert_eq!(NATIVE_SELECT_PERSIST, 3);
        assert_eq!(NATIVE_SELECT_LC, 4);
    }
}

/// A flow-map mutation emitted by the native datapath.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeFlowEvent {
    pub key: NativeFlowKey,
    pub value: NativeFlowValue,
    pub op: u8,
    pub _pad: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NativeDatapathStats {
    pub service_hit: u64,
    pub service_miss: u64,
    pub return_miss: u64,
    pub target_miss: u64,
    pub rewritten: u64,
    pub checksum_error: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NativeServiceKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NativeServiceValue {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NativeEndpointKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NativeEndpointLoadKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NativeEndpointValue {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NativeFlowKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NativeFlowValue {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NativeFlowEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NativeDatapathStats {}
