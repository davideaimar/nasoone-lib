use crate::PacketData;
use crossbeam_channel::{select, tick, Receiver, Sender};
use std::time::Duration;
use crate::Collection;
use crate::PacketKey;

pub(crate) fn parser_task(
    rx_prod_parser: Receiver<PacketData>, 
    tx_parser_writer: Sender<Collection>,
    timeout: u32,
) {
    // the ticker will send an empty message every `timeout` seconds
    let ticker = tick(Duration::from_secs(timeout as u64));
    let mut collection = Collection::new();
    /* Fill the HashMap for trying the writer */
    collection.insert(PacketKey::new("192.168.10.2".to_string(), 3001), PacketData::new(100, vec![1, 2, 3], 10));
    collection.insert(PacketKey::new("192.168.17.66".to_string(), 3000), PacketData::new(150, vec![4, 5, 6], 2000));
    collection.insert(PacketKey::new("192.168.10.204".to_string(), 3001), PacketData::new(40, vec![7, 8, 9], 80));
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
                // here we should send the intermedia data to the writer and clean the local data
                // we need a data structure to collect all the PacketData, I used a dummy data structure for doing concurrency
                tx_parser_writer.send(collection.clone()).unwrap();
            }
        }
    }
    println!("Parser leaving");
}
