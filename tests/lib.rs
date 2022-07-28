use nasoone_lib::Nasoone;
use std::fs::remove_file;

#[test]
fn it_compiles() {
    let mut naso = Nasoone::new();
    naso.set_capture_file("./tests/data/http.pcap").unwrap();
    naso.set_filter("ip host 192.168.1.1").unwrap();
    naso.start().unwrap();
    assert!(Nasoone::list_devices().is_ok());
}

#[test]
fn output_paths() {
    let mut naso = Nasoone::new();
    naso.set_capture_file("./tests/data/http.pcap").unwrap();

    // should fail because ./not/an/existing/dir/ doesn't exist
    assert!(naso.set_output("./not/an/existing/dir/output.txt").is_err());
    // should fail because ./tests/data/http.pcap already exists
    assert!(naso.set_output("./tests/data/http.pcap").is_err());
    // should succeed because ./tests/data/ exists but output.txt doesn't exist
    assert!(naso.set_output("./tests/data/output.txt").is_ok());

    // remove output.txt
    remove_file("./tests/data/output.txt").unwrap();

    naso.start().unwrap();

    // should fail because capture has already been started
    assert!(naso.set_output("./tests/data/output.txt").is_err());
}

#[test]
fn list_devices() {
    let devices = Nasoone::list_devices();
    assert!(devices.is_ok());
    let devices = devices.unwrap();
    assert!(!devices.is_empty());
    // println!("{:?}", devices);
}

#[test]
fn filters() {
    let mut naso = Nasoone::new();
    naso.set_capture_file("./tests/data/http.pcap").unwrap();
    naso.set_filter("tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)")
        .unwrap();
    naso.set_filter("icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply")
        .unwrap();
}
