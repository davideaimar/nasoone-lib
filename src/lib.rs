//! Nasoone-lib is a library for the NASOONE project.
//! It provides a struct for analyzing network traffic using [pcap](https://docs.rs/pcap/latest/pcap/index.html).

mod filter;

use pcap::{Active, Capture, Device};
use crate::filter::Filter;

enum NasooneState {
    Initial,
    Running,
    Paused,
    Stopped,
}

pub struct Nasoone {
    state: NasooneState,
    filter: Option<Filter>,
    timeout: u64,
    capture: Capture<Active>,
    output: String,
}

impl Nasoone {
    fn from_device(device: &str, timeout: u64, dest_file: &str) -> Result<Nasoone, String> {
        let capture = Capture::from_device(device)
            .map_err(|e| format!("{}", e))?;
        let capture = capture
            .promisc(true)
            .immediate_mode(true)
            .open()
            .map_err(|e| format!("{}", e))?;
        Ok(Nasoone {
            state: NasooneState::Initial,
            filter: None,
            timeout,
            capture,
            output: dest_file.to_string(),
        })
    }
    pub fn set_filter(&mut self, filter: Filter) {
        self.filter = Some(filter);
    }
    pub fn start(&mut self) -> Result<(), String> {
        match self.state {
            NasooneState::Initial => {
                self.state = NasooneState::Running;
                let mut cnt = 0;
                while let Ok(_packet) = self.capture.next() {
                    cnt += 1;
                    if cnt > 1_000 {
                        break;
                    }
                }
                Ok(())
            }
            _ => Err(format!("Nasoone is already running"))?,
        }
    }
    pub fn list_devices() -> Result<Vec<String>, String> {
        let devices = Device::list().map_err(|e| format!("{}", e))?;
        let mut device_names = Vec::new();
        for device in devices {
            device_names.push(device.name.to_string());
        }
        Ok(device_names)
    }
}


#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use crate::{Filter, Nasoone};

    #[test]
    fn it_compiles() {
        let mut naso = Nasoone::from_device(
            "en0",
            10,
            "./tmp/output.pcap"
        ).unwrap();
        let mut filter = Filter::new();
        filter.add_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        filter.add_ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
        filter.add_port(80);
        naso.set_filter(filter);
        naso.start().unwrap();
        println!("{:?}", Nasoone::list_devices().unwrap());
    }
}
