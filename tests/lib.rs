use nasoone_lib::{Nasoone, NasooneError};
use std::fs::remove_file;
use std::thread::sleep;
use std::time::Duration;

#[test]
fn it_compiles() {
    let mut naso = Nasoone::new();
    naso.set_capture_file("./tests/data/http.pcap").unwrap();
    naso.set_output("./tests/output/test1").unwrap();
    //naso.set_filter("ip host 192.168.1.1").unwrap();
    naso.start().unwrap();
    assert!(Nasoone::list_devices().is_ok());
    remove_file("./tests/output/test1").unwrap();
}

#[test]
fn output_paths() {
    let mut naso = Nasoone::new();
    naso.set_capture_file("./tests/data/http.pcap").unwrap();

    // should fail because ./not/an/existing/dir/ doesn't exist
    assert!(naso.set_output("./not/an/existing/dir/output").is_err());
    // should fail because ./tests/data/http.pcap already exists
    assert!(naso.set_output("./tests/data/http.pcap").is_err());
    // should succeed because ./tests/data/ exists but output doesn't exist
    assert!(naso.set_output("./tests/output/test2").is_ok());

    naso.start().unwrap();

    // should fail because capture has already been started
    assert!(naso.set_output("./tests/output/test3").is_err());

    remove_file("./tests/output/test2").unwrap();
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

#[test]
fn test_pause_stop() {
    let mut naso = Nasoone::new();
    //naso.set_capture_file("./tests/data/http.pcap").unwrap();
    naso.set_capture_device("en0").unwrap();
    naso.set_output("./tests/output/test4").unwrap();
    naso.start().unwrap();
    println!("Started");
    // try to pause, could fail because the capture has already finished
    let res = naso.pause();
    if res.is_ok() {
        println!("Paused");
    } else {
        match res.err().unwrap() {
            NasooneError::InvalidState(_) => {
                println!("Capture already finished");
                remove_file("./tests/output/test4").unwrap();
                return;
            }
            _ => panic!("Unexpected error"),
        }
    }
    // wait 0.1 second in paused state
    sleep(Duration::from_millis(100));
    // resume the capture
    naso.resume().unwrap();
    println!("Resumed");
    // wait 0.5 second in running state
    sleep(Duration::from_millis(500));
    // stop the capture, could fail because the capture has already finished
    let _ = naso.stop();
    let _ = remove_file("./tests/output/test4");
}
