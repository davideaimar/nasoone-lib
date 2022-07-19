use nasoone_lib::filter::Filter;
use nasoone_lib::Nasoone;
use std::fs::remove_file;
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
    assert_eq!(Nasoone::list_devices().is_err(), false);
}

#[test]
fn output_paths() {
    let mut naso = Nasoone::new();
    naso.set_capture_file("./tests/data/http.pcap").unwrap();

    // should fail because ./not/an/existing/dir/ doesn't exist
    assert_eq!(
        naso.set_output("./not/an/existing/dir/output.txt").is_err(),
        true
    );
    // should fail because ./tests/data/http.pcap already exists
    assert_eq!(naso.set_output("./tests/data/http.pcap").is_err(), true);
    // should succeed because ./tests/data/ exists but output.txt doesn't exist
    assert_eq!(naso.set_output("./tests/data/output.txt").is_err(), false);

    // remove output.txt
    remove_file("./tests/data/output.txt").unwrap();

    naso.start().unwrap();

    // should fail because capture has already been started
    assert_eq!(naso.set_output("./tests/data/output.txt").is_err(), true);
}

#[test]
fn list_devices() {
    assert_eq!(Nasoone::list_devices().is_err(), false);
    assert!(Nasoone::list_devices().unwrap().len() > 0);
}

#[test]
fn filters() {
    let mut filter = Filter::new();
    // empty filter allows everything
    assert!(filter.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    // empty filter allows everything
    assert!(filter.is_ip_allowed(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
    // empty filter allows everything
    assert!(filter.is_port_allowed(80));

    filter.add_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    filter.add_ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
    filter.add_port(80);

    // these should be allowed
    assert!(filter.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    assert!(filter.is_ip_allowed(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
    assert!(filter.is_port_allowed(80));

    // these should be denied
    assert_eq!(
        filter.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
        false
    );
    assert_eq!(
        filter.is_ip_allowed(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2))),
        false
    );
    assert_eq!(filter.is_port_allowed(8080), false);
}
