use nasoone_lib::{Filter, Nasoone, NasooneError, NasooneState};
use std::fs::remove_file;
use std::net::IpAddr;
use std::thread::sleep;
use std::time::{Duration, Instant};

#[test]
fn it_compiles() {
    let mut naso = Nasoone::new();
    naso.set_capture_file("./tests/data/http.pcap").unwrap();
    naso.set_output("./tests/output/test1").unwrap();
    //naso.set_filter("ip host 192.168.1.1").unwrap();
    naso.start().unwrap();
    assert!(Nasoone::list_devices().is_ok());
    let _ = remove_file("./tests/output/test1");
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

    let _ = remove_file("./tests/output/test2");
}

#[test]
fn list_devices() {
    let devices = Nasoone::list_devices();
    assert!(devices.is_ok());
    let devices = devices.unwrap();
    assert!(!devices.is_empty());
    for device in devices {
        assert!(!device.get_name().is_empty());
        let _ = device.get_desc();
    }
    // println!("{:?}", devices);
}

#[test]
fn raw_filters() {
    let mut naso = Nasoone::new();
    naso.set_capture_file("./tests/data/http.pcap").unwrap();
    naso.set_raw_filter(
        "tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)",
    )
    .unwrap();
    naso.set_raw_filter("icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply")
        .unwrap();
}

#[test]
fn filters() {
    let filter = Filter::new()
        .clear_dst_host()
        .clear_host()
        .add_host(IpAddr::V4("192.168.1.1".parse().unwrap()))
        .add_host(IpAddr::V4("192.168.1.2".parse().unwrap()))
        .add_dst_host(IpAddr::V4("224.0.0.251".parse().unwrap()))
        .add_dst_host(IpAddr::V4("224.0.0.252".parse().unwrap()))
        .add_src_host(IpAddr::V4("192.168.1.164".parse().unwrap()))
        .add_src_host(IpAddr::V4("192.168.1.165".parse().unwrap()))
        .add_port(80)
        .add_port(443)
        .set_tcp_only();
    println!("{}", filter);
    let mut naso = Nasoone::new();
    naso.set_capture_file("./tests/data/http.pcap").unwrap();
    naso.set_filter(&filter).unwrap();
}

#[test]
fn empty_filter() {
    let filter = Filter::new();
    println!("{}", filter);
    let mut naso = Nasoone::new();
    naso.set_capture_file("./tests/data/http.pcap").unwrap();
    naso.set_filter(&filter).unwrap();
}

#[test]
fn test_finished_state() {
    let _ = remove_file("./tests/output/test_finished");
    let mut naso = Nasoone::new();
    naso.set_capture_file("./tests/data/http.pcap").unwrap();
    naso.set_output("./tests/output/test_finished").unwrap();
    naso.start().unwrap();
    sleep(Duration::from_secs(1));
    match naso.get_state() {
        NasooneState::Finished => {}
        _ => panic!("Nasoone should be in Finished state"),
    }
    let _ = naso.stop().unwrap();
    remove_file("./tests/output/test_finished").unwrap();
}

#[test]
fn test_pause_stop() {
    let _ = remove_file("./tests/output/test4");
    let mut naso = Nasoone::new();
    naso.set_capture_file("./tests/data/http.pcap").unwrap();
    //naso.set_capture_device("en0").unwrap();
    naso.set_output("./tests/output/test4").unwrap();
    naso.start().unwrap();
    println!("Started");
    // try to pause, could fail because the capture has already finished
    let res = naso.pause();
    if res.is_ok() {
        println!("Paused");
    } else {
        match res.err().unwrap() {
            NasooneError::CaptureOver => {
                println!("Capture already finished");
                remove_file("./tests/output/test4").unwrap();
                return;
            }
            _ => panic!("Unexpected error"),
        }
    }
    // wait 0.1 second in paused state
    sleep(Duration::from_millis(100));
    // try to resume the capture, could fail because it's already finished
    let _ = naso.resume();
    // wait 0.5 second in running state
    sleep(Duration::from_millis(500));
    // stop the capture, could fail because the capture has already finished
    let _ = naso.stop();
    let _ = remove_file("./tests/output/test4");
}

#[test]
#[ignore]
fn test_total_packets_with_interface() {
    let _ = remove_file("./tests/output/test_total_packets_with_interface");
    let mut naso = Nasoone::new();
    naso.set_capture_device("en0").unwrap();
    naso.set_output("./tests/output/test_total_packets_with_interface")
        .unwrap();
    naso.start().unwrap();
    let mut packets = 0;
    for _ in 0..10 {
        sleep(Duration::from_secs(1));
        packets = naso.get_total_packets();
        println!("{} packets", packets);
    }
    let stats = naso.stop().unwrap().unwrap();
    assert!(stats.received as usize >= packets);
    remove_file("./tests/output/test_total_packets_with_interface").unwrap();
}

#[test]
#[ignore]
fn test_total_packets_with_file() {
    let _ = remove_file("./tests/output/test_total_packets_with_file");
    let mut naso = Nasoone::new();
    naso.set_capture_file("./tests/data/http.pcap").unwrap();
    naso.set_output("./tests/output/test_total_packets_with_file")
        .unwrap();
    naso.start().unwrap();
    sleep(Duration::from_secs(1));
    let _ = naso.stop().unwrap();
    assert_eq!(naso.get_total_packets(), 43);
    remove_file("./tests/output/test_total_packets_with_file").unwrap();
}

#[test]
#[ignore]
fn test_device_list() {
    let _ = remove_file("./tests/output/test_device_list");
    let devices = Nasoone::list_devices().unwrap();
    println!("{:?}", devices);
}

#[test]
#[ignore] // ignored because need privileged access, and it is not available on the CI
          // test that the absence of valid packets will not block the stop() function
fn test_filter_stop() {
    let _ = remove_file("./tests/output/test5");
    let mut naso = Nasoone::new();
    naso.set_capture_device(Nasoone::get_default_device_name().unwrap().as_str())
        .unwrap();
    naso.set_output("./tests/output/test5").unwrap();
    naso.set_timeout(10).unwrap();
    naso.set_raw_filter("host 1.2.3.4").unwrap();
    naso.start().unwrap();
    sleep(Duration::from_secs(1));
    naso.stop().unwrap();
    let _ = remove_file("./tests/output/test5");
}

#[test]
#[ignore] // ignored because need privileged access, and it is not available on the CI
fn test_no_lost_packets() {
    let _ = remove_file("./tests/output/test6");
    let mut naso = Nasoone::new();
    naso.set_capture_device(Nasoone::get_default_device_name().unwrap().as_str())
        .unwrap();
    naso.set_output("./tests/output/test6").unwrap();
    naso.set_timeout(10).unwrap();
    naso.set_raw_filter("host 1.2.3.4").unwrap();
    naso.start().unwrap();
    sleep(Duration::from_secs(1));
    let start = Instant::now();
    let stats = naso.stop().unwrap();
    let duration = start.elapsed();
    println!("Duration of stop function: {:?}", duration);
    match stats {
        Some(stats) => {
            println!("{:?}", stats);
            assert_eq!(stats.dropped, 0);
        }
        None => panic!("No stats found"),
    }
    let _ = remove_file("./tests/output/test6");
}

#[test]
#[ignore]
fn test_stop_duration() {
    let _ = remove_file("./tests/output/test7");
    let mut naso = Nasoone::new();
    naso.set_capture_device(Nasoone::get_default_device_name().unwrap().as_str())
        .unwrap();
    naso.set_output("./tests/output/test7").unwrap();
    naso.start().unwrap();
    sleep(Duration::from_millis(5000));
    let start = Instant::now();
    let stats = naso.stop().unwrap();
    let duration = start.elapsed();
    println!("Duration of stop function: {:?}", duration);
    if let Some(stats) = stats {
        println!("{:?}", stats);
    }
    let _ = remove_file("./tests/output/test7");
}

#[test]
fn test_pcap_file_1() {
    let mut naso = Nasoone::new();
    naso.set_capture_file("./tests/data/wireshark/wireshark_1.pcap")
        .unwrap();
    naso.set_output("./tests/output/test8").unwrap();
    naso.start().unwrap();
    let _ = remove_file("./tests/output/test8");
}

#[test]
fn test_pcap_file_2() {
    let mut naso = Nasoone::new();
    naso.set_capture_file("./tests/data/wireshark/wireshark_3.pcap")
        .unwrap();
    naso.set_output("./tests/output/test9").unwrap();
    naso.start().unwrap();
    let _ = remove_file("./tests/output/test9");
}
