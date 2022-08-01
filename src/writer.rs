use std::{fs::File, io::Write};
use crossbeam_channel::{Receiver};
use crate::Collection;

pub(crate) fn writer_task(
    rx_parser_writer: Receiver<Collection>,
    output_file: &mut File,
) {
    loop {
        let collection: Collection = rx_parser_writer.recv().unwrap();
        collection.packets.keys().for_each(|k| {
            let pack = collection.get(k);
            // I implemented the Display trait both for PacketKey and PacketData
            let res = write!(output_file, "{} {}", k, pack);
            match res {
                Ok(()) => println!("Writing successful!"),
                Err(error) => panic!("Problems with writing, error: {}", error),
            }
        });
    }

}
