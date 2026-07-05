//! Network enrichment — map each pid to its TCP connections via `netstat2`. One syscall
//! surfaces the whole table; we group by owning pid. Used for display (what a process is
//! talking to) and lightweight heuristics.

use std::collections::HashMap;

use netstat2::{
    get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState,
};

use crate::model::NetworkConn;

/// All TCP connections grouped by owning pid. Returns an empty map on error (best-effort).
pub fn connections_by_pid() -> HashMap<u32, Vec<NetworkConn>> {
    let mut map: HashMap<u32, Vec<NetworkConn>> = HashMap::new();
    let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let sockets = match get_sockets_info(af, ProtocolFlags::TCP) {
        Ok(s) => s,
        Err(_) => return map,
    };
    for si in sockets {
        let ProtocolSocketInfo::Tcp(tcp) = si.protocol_socket_info else {
            continue;
        };
        let conn = NetworkConn {
            remote_addr: tcp.remote_addr.to_string(),
            remote_port: tcp.remote_port,
            state: format!("{:?}", tcp.state),
        };
        for pid in si.associated_pids {
            map.entry(pid).or_default().push(conn.clone());
        }
    }
    map
}

/// Whether a connection is to a non-loopback, non-unspecified remote (i.e. talking off-box).
pub fn is_remote(conn: &NetworkConn) -> bool {
    use std::net::IpAddr;
    match conn.remote_addr.parse::<IpAddr>() {
        Ok(ip) => !ip.is_loopback() && !ip.is_unspecified(),
        Err(_) => false,
    }
}

/// True if `conns` contains at least one established connection to an off-box remote.
pub fn has_established_remote(conns: &[NetworkConn]) -> bool {
    established_remote_count(conns) > 0
}

/// Number of established connections to off-box remotes.
pub fn established_remote_count(conns: &[NetworkConn]) -> usize {
    let established = format!("{:?}", TcpState::Established);
    conns.iter().filter(|c| c.state == established && is_remote(c)).count()
}
