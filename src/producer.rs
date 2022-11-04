use crate::{Command, NasooneCapture, PacketData};
use crossbeam_channel::{Receiver, Sender, TryRecvError};
use pcap::{Error, Stat};
use std::sync::{Arc, Mutex};

// The producer thread. Its task is to receive packets from pcap, clone the data and send it to a
// parser thread that is available. At every packet received, the producer also check the state:
//  - `NasooneState::Stopped` will stop the capture, dropping the Sender to the parsers will cause the
//    parser threads to stop.
// - `NasooneState::Paused` will pause the capture.
// - `NasooneState::Running` or `NasooneState::Initial` will continue the capture.
pub(crate) fn producer_task(
    mut capture: NasooneCapture,
    tx_prod_parser: Sender<PacketData>,
    rx_main_prod: Receiver<Command>,
    total_packets: Arc<Mutex<usize>>,
) -> Result<Stat, Error> {
    let mut ignore_packets = false;

    let from_file = matches!(capture, NasooneCapture::FromFile(_));

    let mut packet_cnt: usize = 0;

    loop {
        // after every packet received, check if there is a command from the main thread

        if from_file && ignore_packets {
            // BLOCKING wait if the capture is from a file and we are ignoring packets,
            // because capturing from a file we don't want to loose packets
            match rx_main_prod.recv() {
                Ok(Command::Stop) => break,
                Ok(Command::Pause) => ignore_packets = true,
                Ok(Command::Resume) => ignore_packets = false,
                Err(_) => break,
            }
        } else {
            // NON-BLOCKING wait if the capture is from a device
            match rx_main_prod.try_recv() {
                Ok(Command::Stop) => break,
                Ok(Command::Pause) => ignore_packets = true,
                Ok(Command::Resume) => ignore_packets = false,
                Err(err) => match err {
                    TryRecvError::Empty => (),
                    TryRecvError::Disconnected => break,
                },
            }
        }

        if from_file && ignore_packets {
            // we don't want to get next packet, we just need to wait for a resume/stop command
            continue;
        }

        // receive next packet (blocking), could exit after a timeout if no packet is received
        // or if no packet satisfies the filter. The timeout is set when the capture is built (200ms).
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

        if !ignore_packets {
            packet_cnt += 1;
            // update the total packets counter every 10 packets
            if packet_cnt % 10 == 0 {
                *total_packets.lock().unwrap() = packet_cnt;
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
    }
    match capture {
        NasooneCapture::FromDevice(mut capture) => capture.stats(),
        NasooneCapture::FromFile(mut capture) => capture.stats(),
    }
}
