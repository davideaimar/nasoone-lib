use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;

pub struct Filter {
    //Filter by address
    hosts: HashMap<IpAddr, bool>,
    src_hosts: HashMap<IpAddr, bool>,
    dst_hosts: HashMap<IpAddr, bool>,

    //Filter by protocol
    tcp: bool,
    udp: bool,

    //Filter by port
    ports: HashSet<u16>,
    src_ports: HashSet<u16>,
    dst_ports: HashSet<u16>,
}

impl Default for Filter {
    fn default() -> Self {
        Self::new()
    }
}

impl Filter {
    //Constructor
    pub fn new() -> Self {
        Filter {
            hosts: HashMap::new(),
            src_hosts: HashMap::new(),
            dst_hosts: HashMap::new(),

            tcp: true,
            udp: true,

            ports: HashSet::new(),
            src_ports: HashSet::new(),
            dst_ports: HashSet::new(),
        }
    }

    /// Adds an ip host to the filter. It clears the src and dst hosts.
    /// Ips added here can match both src and dst hosts.
    ///
    /// # Arguments
    ///
    /// * `host` - The ip address to add to the filter.
    /// * `not` - If true, only packets that do not include the ip address will be captured.
    ///
    pub fn add_host(mut self, host: IpAddr, not: bool) -> Self {
        self.hosts.insert(host, not);
        self.src_hosts.clear(); //host filter mutual exclusive with src and dst
        self.dst_hosts.clear();
        self
    }

    /// Adds a src ip host to the filter. It clears the general hosts.
    /// Ips added here must be present as the src host of packets.
    ///
    /// # Arguments
    ///
    /// * `src_host` - The ip address to add to the filter.
    /// * `not` - If true, only packets that do not include the ip address as source will be captured.
    ///
    pub fn add_src_host(mut self, src_host: IpAddr, not: bool) -> Self {
        self.src_hosts.insert(src_host, not);
        self.hosts.clear();
        self
    }

    /// Adds a dest ip host to the filter. It clears the general hosts.
    /// Ips added here must be present as the dest host of packets.
    ///
    /// # Arguments
    ///
    /// * `dst_host` - The ip address to add to the filter.
    /// * `not` - If true, only packets that do not include the ip address as source will be captured.
    ///
    pub fn add_dst_host(mut self, dst_host: IpAddr, not: bool) -> Self {
        self.dst_hosts.insert(dst_host, not);
        self.hosts.clear();
        self
    }

    /// Deletes all the previously added IP hosts.
    pub fn clear_host(mut self) -> Self {
        self.hosts.clear();
        self
    }

    /// Deletes all the previously added source IP hosts.
    pub fn clear_src_host(mut self) -> Self {
        self.src_hosts.clear();
        self
    }

    /// Deletes all the previously added dest IP hosts.
    pub fn clear_dst_host(mut self) -> Self {
        self.dst_hosts.clear();
        self
    }

    /// Detect only tcp packets.
    pub fn set_tcp_only(mut self) -> Self {
        self.tcp = true;
        self.udp = false;
        self
    }

    /// Detect only udp packets.
    pub fn set_udp_only(mut self) -> Self {
        self.udp = true;
        self.tcp = false;
        self
    }

    /// Detect both tcp and udp packets.
    pub fn clear_protocol(mut self) -> Self {
        self.udp = true;
        self.tcp = true;
        self
    }

    /// Add an accepted port to the filter. Matches both src and dst ports. It clears the src and dst ports.
    ///
    /// # Arguments
    ///
    /// * `port` - The valid port to add to the filter.
    pub fn add_port(mut self, port: u16) -> Self {
        self.ports.insert(port);
        self.src_ports.clear(); //Mutually exclusive with src and dst port
        self.dst_ports.clear();
        self
    }

    /// Add an accepted source port to the filter. It clears the general ports.
    ///
    /// # Arguments
    ///
    /// * `src_port` - The source port to accept.
    pub fn add_src_port(mut self, src_port: u16) -> Self {
        self.src_ports.insert(src_port);
        self.ports.clear(); //Mutually exclusive with port
        self
    }

    /// Add an accepted dest port to the filter. It clears the generic ports.
    ///
    /// # Arguments
    ///
    /// * `dst_port` - The destination port to accept.
    pub fn add_dst_port(mut self, dst_port: u16) -> Self {
        self.dst_ports.insert(dst_port);
        self.ports.clear(); //Mutually exclusive with port
        self
    }
}

impl fmt::Display for Filter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut output = "".to_owned();
        //IP ADDRESSES
        if !self.hosts.is_empty() {
            output += "(";
            output += self
                .hosts
                .clone()
                .into_iter()
                .filter(|(_, not)| !*not)
                .map(|(host, _)| format!("host {}", host))
                .collect::<Vec<String>>()
                .join(" or ")
                .as_str();
            output += ") and (";
            output += self
                .hosts
                .clone()
                .into_iter()
                .filter(|(_, not)| *not)
                .map(|(host, _)| format!("not host {}", host))
                .collect::<Vec<String>>()
                .join(" or ")
                .as_str();
            output += ") and ";
        } else {
            if !self.src_hosts.is_empty() {
                output += "(";
                output += self
                    .src_hosts
                    .clone()
                    .into_iter()
                    .filter(|(_, not)| !*not)
                    .map(|(host, _)| format!("src host {}", host))
                    .collect::<Vec<String>>()
                    .join(" or ")
                    .as_str();
                output += ") and (";
                output += self
                    .src_hosts
                    .clone()
                    .into_iter()
                    .filter(|(_, not)| *not)
                    .map(|(host, _)| format!("not src host {}", host))
                    .collect::<Vec<String>>()
                    .join(" or ")
                    .as_str();
                output += ") and ";
            }
            if !self.dst_hosts.is_empty() {
                output += "(";
                output += self
                    .dst_hosts
                    .clone()
                    .into_iter()
                    .filter(|(_, not)| !*not)
                    .map(|(host, _)| format!("dst host {}", host))
                    .collect::<Vec<String>>()
                    .join(" or ")
                    .as_str();
                output += ") and (";
                output += self
                    .dst_hosts
                    .clone()
                    .into_iter()
                    .filter(|(_, not)| *not)
                    .map(|(host, _)| format!("not dst host {}", host))
                    .collect::<Vec<String>>()
                    .join(" or ")
                    .as_str();
                output += ") and ";
            }
        }

        //PORTS
        if !self.ports.is_empty() {
            output += "( port ";
            output += self
                .ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<String>>()
                .join(" or port ")
                .as_str();
            output += ") and ";
        } else {
            if !self.src_ports.is_empty() {
                output += "( src port ";
                output += self
                    .src_ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<String>>()
                    .join(" or src port ")
                    .as_str();
                output += ") and ";
            }
            if !self.dst_ports.is_empty() {
                output += "( dst port ";
                output += self
                    .dst_ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<String>>()
                    .join(" or dst port ")
                    .as_str();
                output += ") and ";
            }
        }

        if self.tcp && !self.udp {
            output += "http and ";
        }
        if self.udp && !self.tcp {
            output += "udp and ";
        }

        let output = &output[0..output.len() - 5]; //Removes the trailing " and "
        write!(f, "{}", output)
    }
}
