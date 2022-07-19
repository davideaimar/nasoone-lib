use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct Filter {
    ports: HashSet<u16>,
    ipv4: HashSet<Ipv4Addr>,
    ipv6: HashSet<Ipv6Addr>,
}

impl Filter {
    pub fn new() -> Filter {
        Filter {
            ports: HashSet::new(),
            ipv4: HashSet::new(),
            ipv6: HashSet::new(),
        }
    }
    pub fn add_port(&mut self, port: u16) {
        self.ports.insert(port);
    }
    pub fn add_ip(&mut self, ip: IpAddr) {
        match ip {
            IpAddr::V4(ip) => self.ipv4.insert(ip),
            IpAddr::V6(ip) => self.ipv6.insert(ip),
        };
    }
    pub fn is_port_allowed(&self, port: u16) -> bool {
        self.ports.is_empty() || self.ports.contains(&port)
    }
    pub fn is_ip_allowed(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => self.ipv4.is_empty() || self.ipv4.contains(&ip),
            IpAddr::V6(ip) => self.ipv6.is_empty() || self.ipv6.contains(&ip),
        }
    }
}

impl Default for Filter {
    fn default() -> Self {
        Self::new()
    }
}
