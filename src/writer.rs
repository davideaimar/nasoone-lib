use crate::{ReportKey, ReportValue};
use crossbeam_channel::{select, tick, Receiver};
use std::collections::{HashMap, HashSet};
use std::io::{Seek, SeekFrom};
use std::time::Duration;
use std::{fs::File, io::Write};

fn overwrite_file(file: &mut File, data: &HashMap<ReportKey, ReportValue>) -> std::io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    writeln!(
        file,
        "source ip; source port; destination ip; destination port; protocols; first; last; bytes; packets"
    )
    .expect("Failed to write to file");
    data.iter().for_each(|entry| {
        writeln!(file, "{}; {}", entry.0, entry.1).expect("Failed to write to file");
    });
    Ok(())
}

pub(crate) fn writer_task(
    rx_parser_writer: Receiver<HashMap<ReportKey, ReportValue>>,
    output_file: &mut File,
    timeout_s: u32,
) {
    let ticker = tick(Duration::from_secs(timeout_s as u64));
    let mut global_map = HashMap::new();
    loop {
        select! {
            recv(rx_parser_writer) -> map => {
                if let Ok(map) = map {
                    for (key, value) in map.into_iter() {
                        let mut info = global_map.entry(key).or_insert(ReportValue {
                            protocols: HashSet::new(),
                            first_timestamp_ms: value.first_timestamp_ms,
                            last_timestamp_ms: value.first_timestamp_ms,
                            bytes: 0,
                            packets_count: 0,
                        });
                        info.protocols.extend(value.protocols);
                        info.bytes += value.bytes;
                        info.last_timestamp_ms = info.last_timestamp_ms.max(value.last_timestamp_ms);
                        info.first_timestamp_ms = info.first_timestamp_ms.min(value.first_timestamp_ms);
                        info.packets_count += value.packets_count;
                    }
                } else {
                    break;
                }
            },
            recv(ticker) -> _ => {
                overwrite_file(output_file, &global_map).unwrap();
            }
        }
    }
    overwrite_file(output_file, &global_map).unwrap();
}
