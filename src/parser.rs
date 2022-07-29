use crate::PacketData;
use crossbeam_channel::{select, tick, Receiver};
use std::time::Duration;

pub(crate) fn parser_task(rx_prod_parser: Receiver<PacketData>, timeout: u32) {
    // the ticker will send an empty message every `timeout` seconds
    let ticker = tick(Duration::from_secs(timeout as u64));
    loop {
        select! {
            recv(rx_prod_parser) -> packet => {
                if let Ok(data) = packet {
                    // TODO: manage packet info
                    let _ts = data.timestamp;
                    let _bytes = data.bytes;
                    let _packet = data.data;
                    println!("Packet received at {}", _ts);
                } else {
                    break;
                }
            }
            recv(ticker) -> _ => {
                println!("*Unloading*");
                // here we should send the intermedia data to the writer and clean the local data
            }
        }
    }
    println!("Parser leaving");
}
