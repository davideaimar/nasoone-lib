use std::fmt;
use std::net::IpAddr;

pub struct Filter {
    //Filter by address
    hosts:          Vec<String>,
    src_hosts:      Vec<String>,
    dst_hosts:      Vec<String>,
    ether_host:     String,
    ether_src_host: String,
    ether_dst_host: String,

    //Filter by protocol
    http: bool,
    tcp: bool,
    ftp: bool,
    udp: bool,
    dns: bool,
    icmp: bool,
    smtp: bool,

    //Filter by port
    port: i32,
    src_port: i32,
    dst_port: i32,
}

impl Filter {
    //Constructor
    pub fn new() -> Self {
        Filter {
            hosts:          Vec::new(),
            src_hosts:      Vec::new(),
            dst_hosts:      Vec::new(),
            ether_host:     "".to_string(),
            ether_src_host: "".to_string(),
            ether_dst_host: "".to_string(),

            http: false,
            tcp: false,
            ftp: false,
            udp: false,
            dns: false,
            icmp: false,
            smtp: false,

            port: 0,
            src_port: 0,
            dst_port: 0,
        }
    }

    //IP ADDRESSES
    pub fn add_host(&mut self, host: IpAddr, not: bool) {
        let mut s = "".to_string();
        if not {
            s += "not ";
        }
        s += "host ";
        s += host.to_string().as_str();
        self.hosts.push(s);
        self.src_hosts.clear(); //host filter mutual exclusive with src and dst
        self.dst_hosts.clear();
    }
    pub fn add_src_host(&mut self, src_host: IpAddr, not: bool) {
        let mut s = "".to_string();
        if not {
            s += "not ";
        }
        s += "src host ";
        s += src_host.to_string().as_str();
        self.src_hosts.push(s);
        self.hosts.clear();
    }
    pub fn add_dst_host(&mut self, dst_host: IpAddr, not: bool) {
        let mut s = "".to_string();
        if not {
            s += "not ";
        }
        s += "dst host ";
        s += dst_host.to_string().as_str();
        self.dst_hosts.push(s);
        self.hosts.clear();
    }
    pub fn remove_host(&mut self, ) {

    }
    pub fn clear_host(&mut self) {
        self.hosts.clear();
    }
    pub fn clear_src_host(&mut self) {
        self.src_hosts.clear();
    }
    pub fn clear_dst_host(&mut self) {
        self.dst_hosts.clear();
    }

    //MAC ADDRESSES
    pub fn set_ether_host(&mut self, ether_host: String, not: bool) {
        if not {
            self.ether_host = "not ".to_string();
        }
        self.ether_host += "ether host ";
        self.ether_host += ether_host.as_str();
        self.ether_src_host.clear(); //ether_host filter mutual exclusive with src and dst
        self.ether_dst_host.clear();
    }
    pub fn set_ether_src_host(&mut self, ether_src_host: String, not: bool) {
        if not {
            self.ether_src_host = "not ".to_string();
        }
        self.ether_src_host += "ether src host ";
        self.ether_src_host += ether_src_host.as_str();
        self.ether_host.clear();
    }
    pub fn set_ether_dst_host(&mut self, ether_dst_host: String, not: bool) {
        if not {
            self.ether_dst_host = "not ".to_string();
        }
        self.ether_dst_host += "ether dst host ";
        self.ether_dst_host += ether_dst_host.as_str();
        self.ether_host.clear();
    }

    //PROTOCOLS
    pub fn set_http(&mut self, http: bool) {self.http = http;}
    pub fn set_tcp(&mut self, tcp: bool)   {self.tcp  = tcp;}
    pub fn set_udp(&mut self, udp: bool)   {self.udp  = udp;}
    pub fn set_dns(&mut self, dns: bool)   {self.dns  = dns;}
    pub fn set_smtp(&mut self, smtp: bool) {self.smtp = smtp;}

    //PORTS
    pub fn set_port(&mut self, port: i32) {
        self.port = port;
        self.src_port = 0; //Mutually exclusive with src and dst port
        self.dst_port = 0;
    }
    pub fn set_src_port(&mut self, src_port: i32) {
        self.src_port = src_port;
        self.port = 0; //Mutually exclusive with port
    }
    pub fn set_dst_port(&mut self, dst_port: i32) {
        self.dst_port = dst_port;
        self.port = 0; //Mutually exclusive with port
    }
}

impl fmt::Display for Filter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut output = "".to_owned();
        //IP ADDRESSES
        if self.hosts.len() != 0 {
            if self.hosts.len() == 1 {output += self.hosts[0].as_str(); output += " and ";}
            else {
                output += "(";
                output += self.hosts[0].as_str();
                for i in 1..self.hosts.len() {
                    output += " or ";
                    output += self.hosts[i].as_str();
                }
                output += ") and ";
            }
        } else {
            if self.src_hosts.len() == 1 {output += self.src_hosts[0].as_str(); output += " and ";}
            else {
                output += "(";
                output += self.src_hosts[0].as_str();
                for i in 1..self.src_hosts.len() {
                    output += " or ";
                    output += self.src_hosts[i].as_str();
                }
                output += ") and ";
            }
            if self.dst_hosts.len() == 1 {output += self.dst_hosts[0].as_str(); output += " and ";}
            else {
                output += "(";
                output += self.dst_hosts[0].as_str();
                for i in 1..self.dst_hosts.len() {
                    output += " or ";
                    output += self.dst_hosts[i].as_str();
                }
                output += ") and ";
            }
        }

        //MAC ADDRESSES
        if self.ether_host != "" {
            output += self.ether_host.as_str();
            output += " and ";
        }
        if self.ether_src_host != "" {
            output += self.ether_src_host.as_str();
            output += " and ";
        }
        if self.ether_dst_host != "" {
            output += self.ether_dst_host.as_str();
            output += " and ";
        }

        //PORTS
        if self.port != 0 {
            output += "port ";
            output += self.port.to_string().as_str();
            output += " and ";
        }
        if self.src_port != 0 {
            output += "src port ";
            output += self.src_port.to_string().as_str();
            output += " and ";
        }
        if self.dst_port != 0 {
            output += "dst port ";
            output += self.dst_port.to_string().as_str();
            output += " and ";
        }

        //PROTOCOLS
        if self.http {
            output += "http and ";
        }
        if self.tcp {
            output += "http and ";
        }
        if self.ftp {
            output += "http and ";
        }
        if self.udp {
            output += "udp and ";
        }
        if self.dns {
            output += "dns and ";
        }
        if self.icmp {
            output += "icmp and ";
        }
        if self.smtp {
            output += "smtp and ";
        }

        let output = &output[0..output.len() - 5]; //Removes the trailing " and "
        write!(f, "{}", output)
    }
}
