use crate::{NasooneCapture, NasooneState, PacketData};
use crossbeam_channel::Sender;
use std::sync::{Arc, Condvar, Mutex};

pub(crate) fn producer_task(
    mut capture: NasooneCapture,
    tx_prod_parser: Sender<PacketData>,
    state: Arc<(Condvar, Mutex<NasooneState>)>,
) -> usize {
    let mut cnt: usize = 0;
    while let Ok(packet) = capture.next() {
        cnt += 1;
        // tv_sec is time in sec, tv_usec is time in microsecond. Result is in millisecond.
        let timestamp =
            packet.header.ts.tv_sec as u64 * 1000 + packet.header.ts.tv_usec as u64 / 1000;
        let data = packet.data.to_vec();
        let bytes = packet.header.caplen;
        // send packet to parsers
        tx_prod_parser
            .send(PacketData {
                timestamp,
                data,
                bytes,
            })
            .unwrap();
        // check if the state is changed
        let mutex = state.1.lock().unwrap();
        match *mutex {
            NasooneState::Stopped => {
                break;
            }
            NasooneState::Paused => {
                let state = state
                    .0
                    .wait_while(mutex, |state| *state == NasooneState::Paused)
                    .unwrap();
                if *state == NasooneState::Stopped {
                    break;
                }
            }
            _ => {}
        }
    }
    *state.1.lock().unwrap() = NasooneState::Stopped;
    println!("producer_task: {} packets processed", cnt);
    cnt
}
