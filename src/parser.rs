use crate::PacketData;
use crossbeam_channel::Receiver;

pub(crate) fn parser_task(rx_prod_parser: Receiver<PacketData>) {
    while let Ok(data) = rx_prod_parser.recv() {
        // TODO: get packet info
        let _ts = data.timestamp;
        let _bytes = data.bytes;
        let _packet = data.data;
    }
}
