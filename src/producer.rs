use crate::{NasooneCapture, NasooneCommand, PacketData};
use crossbeam_channel::{Receiver, Sender};

pub(crate) fn producer_task(
    mut capture: NasooneCapture,
    tx_prod_parser: Sender<PacketData>,
    rx_main_prod: Receiver<NasooneCommand>,
) -> usize {
    let mut cnt: usize = 0;
    while let Ok(packet) = capture.next() {
        cnt += 1;
        // tv_sec is time in sec, tv_usec is time in microsecond. Result is in millisecond.
        let timestamp =
            packet.header.ts.tv_sec as u64 * 1000 + packet.header.ts.tv_usec as u64 / 1000;
        let data = packet.data.to_vec();
        let bytes = packet.header.caplen;
        tx_prod_parser
            .send(PacketData {
                timestamp,
                data,
                bytes,
            })
            .unwrap();
        let command = rx_main_prod.try_recv();
        match command {
            Ok(NasooneCommand::Stop) => {
                break;
            }
            Ok(NasooneCommand::Pause) => loop {
                match rx_main_prod.recv() {
                    Ok(NasooneCommand::Resume) => break,
                    Ok(NasooneCommand::Stop) => break,
                    _ => {}
                }
            },
            _ => {}
        };
    }
    cnt
}
