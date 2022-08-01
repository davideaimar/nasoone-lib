use crate::{AddressType, PacketData, ReportKey, ReportValue};
use crossbeam_channel::{select, tick, Receiver};
use etherparse::PacketHeaders;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

pub(crate) fn parser_task(rx_prod_parser: Receiver<PacketData>, timeout: u32) {
    // the ticker will send an empty message every `timeout` seconds
    let ticker = tick(Duration::from_secs(timeout as u64));
    let mut map: HashMap<ReportKey, ReportValue> = HashMap::new();
    loop {
        select! {
            recv(rx_prod_parser) -> packet => {
                if let Ok(data) = packet {
                    let ts = data.timestamp_ms;
                    let bytes = data.bytes;
                    let packet = data.data;
                    match PacketHeaders::from_ethernet_slice(&packet){
                        Err(value) => println!("Err {:?}", value),
                        Ok(value) => {
                            if value.ip.is_some() && value.transport.is_some() {
                                let ports = match value.transport.unwrap() {
                                    etherparse::TransportHeader::Tcp(value) => (value.source_port, value.destination_port, 6),
                                    etherparse::TransportHeader::Udp(value) => (value.source_port, value.destination_port, 17),
                                    _ => continue,
                                };
                                let ip_header = value.ip.unwrap();
                                let ip_info = match ip_header {
                                    etherparse::IpHeader::Version4(value, ..) => (IpAddr::V4(Ipv4Addr::from(value.source)), IpAddr::V4(Ipv4Addr::from(value.destination))),
                                    etherparse::IpHeader::Version6(value, ..) => (IpAddr::V6(Ipv6Addr::from(value.source)), IpAddr::V6(Ipv6Addr::from(value.destination))),
                                };
                                let key_src = ReportKey {
                                    ip: ip_info.0,
                                    port: ports.0,
                                    dir: AddressType::Src,
                                };
                                let mut info = map.entry(key_src).or_insert(ReportValue {
                                    protocols: HashSet::new(),
                                    first_timestamp_ms: ts,
                                    last_timestamp_ms: ts,
                                    bytes: 0,
                                });
                                info.protocols.insert(ports.2);
                                info.bytes += bytes as u64;
                                info.last_timestamp_ms = info.last_timestamp_ms.max(ts);
                                info.first_timestamp_ms = info.first_timestamp_ms.min(ts);
                                let key_dest = ReportKey {
                                    ip: ip_info.1,
                                    port: ports.1,
                                    dir: AddressType::Dest,
                                };
                                let mut info = map.entry(key_dest).or_insert(ReportValue {
                                    protocols: HashSet::new(),
                                    first_timestamp_ms: ts,
                                    last_timestamp_ms: ts,
                                    bytes: 0,
                                });
                                info.protocols.insert(ports.2);
                                info.bytes += bytes as u64;
                                info.last_timestamp_ms = info.last_timestamp_ms.max(ts);
                                info.first_timestamp_ms = info.first_timestamp_ms.min(ts);

                            }
                        }
                    }
                } else {
                    break;
                }
            }
            recv(ticker) -> _ => {
                println!("Unloading: {:?}", map);
            }
        }
    }
    println!("Parser leaving: {:?}", map);
}
