use crate::{NasooneCapture, NasooneState, PacketData};
use crossbeam_channel::Sender;
use pcap::{Error, Stat};
use std::sync::{Arc, Condvar, Mutex};

/// The producer thread. Its task is to receive packets from pcap, clone the data and send it to a
/// parser thread that is available. At every packet received, the producer also check the state:
///  - `NasooneState::Stopped` will stop the capture, dropping the Sender to the parsers will cause the
///    parser threads to stop.
/// - `NasooneState::Paused` will pause the capture.
/// - `NasooneState::Running` or `NasooneState::Initial` will continue the capture.
pub(crate) fn producer_task(
    mut capture: NasooneCapture,
    tx_prod_parser: Sender<PacketData>,
    state: Arc<(Condvar, Mutex<NasooneState>)>,
) -> Result<Stat, Error> {
    loop {
        // check if the state has changed
        {
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

        // receive next packet (blocking), could exit after a timeout if no packet is received
        // or if no packet satisfies the filter.
        let next_packet = capture.next();
        if next_packet.is_err() {
            match next_packet.err().unwrap() {
                Error::TimeoutExpired => {
                    // ignore timeout, continue and check the state
                    continue;
                }
                Error::NoMorePackets => {
                    // capture is from a file and there are no more packets to read, so we can stop
                    break;
                }
                _ => {
                    // The other errors are not returned by next()
                    continue;
                }
            }
        }
        let packet = next_packet.unwrap();
        // tv_sec is time in sec, tv_usec is time in microsecond. Result is in millisecond.
        let timestamp_ms =
            packet.header.ts.tv_sec as u64 * 1000 + packet.header.ts.tv_usec as u64 / 1000;
        let data = packet.data.to_vec();
        let bytes = packet.header.caplen;
        // send packet to a parser thread that is available
        tx_prod_parser
            .send(PacketData {
                timestamp_ms,
                data,
                bytes,
            })
            .unwrap();
    }
    *state.1.lock().unwrap() = NasooneState::Stopped;
    match capture {
        NasooneCapture::FromDevice(mut capture) => capture.stats(),
        NasooneCapture::FromFile(mut capture) => capture.stats(),
    }
}
