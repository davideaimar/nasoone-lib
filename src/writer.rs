use std::{fs::File, io::Write};
use crossbeam_channel::{Receiver};
use crate::Collection;

pub(crate) fn writer_task(
    rx_parser_writer: Receiver<Collection>,
    output_file: &mut File,
) {
    let collection: Collection = rx_parser_writer.recv().unwrap();
    println!("Here writer");
    /*match res {
        Ok(()) => println!("Everything went well!"),
        Err(_) => {},
    }*/
}
