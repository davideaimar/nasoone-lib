use nasoone_lib::filter::Filter;
use nasoone_lib::Nasoone;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn it_compiles() {
    let mut naso = Nasoone::new();
    let mut filter = Filter::new();
    filter.add_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    filter.add_ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
    filter.add_port(80);
    naso.set_filter(filter).unwrap();
    naso.set_capture_file("./tests/data/http.pcap").unwrap();
    naso.start().unwrap();
    println!("{:?}", Nasoone::list_devices().unwrap());
}
