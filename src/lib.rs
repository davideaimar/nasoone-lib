//! Nasoone-lib is a library for the NASOONE project.
//!
//! It provides an easy way for analyzing network traffic using pcap.
//!
//! The output is a CSV file with the following columns separated by a semicolon:
//! - Source IP
//! - Source port
//! - Destination IP
//! - Destination port
//! - List of observed protocols
//! - Timestamp of the first packet
//! - Timestamp of the last packet
//! - Number of bytes
//! - Number of packets
//!
//! Example usage:
//! ```
//! use std::thread::sleep;
//! use std::time::Duration;
//! use nasoone_lib::Nasoone;
//!
//! let mut naso = Nasoone::new();
//! // set the capture device from a physical interface
//! naso.set_capture_device("en0").unwrap();
//! naso.set_output("./report.csv").unwrap();
//! // set the timeout between report updates (in seconds)
//! naso.set_timeout(1).unwrap();
//! // start the capture (non-blocking)
//! naso.start().unwrap();
//! sleep(Duration::from_secs(10));
//! // pause the capture
//! naso.pause().unwrap();
//! sleep(Duration::from_secs(2));
//! // resume the capture
//! naso.resume().unwrap();
//! sleep(Duration::from_secs(10));
//! // stop the capture and get the stats
//! let stats = naso.stop().unwrap();
//! println!("{:?}", stats);
//! ```

mod parser;
mod producer;
mod writer;

use crate::parser::parser_task;
use crate::producer::producer_task;
use crate::writer::writer_task;
use crossbeam_channel::Sender;
use pcap::{Active, Capture, Device, Offline, Stat};
use std::collections::HashSet;
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::fs::File;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Hash, Eq, PartialEq, Debug)]
enum AddressType {
    Src,
    Dest,
}

impl Display for AddressType {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            AddressType::Src => write!(f, "src"),
            AddressType::Dest => write!(f, "dest"),
        }
    }
}

enum Command {
    Stop,
    Pause,
    Resume,
}

#[derive(Hash, Eq, PartialEq, Debug)]
struct ReportKey {
    ip: IpAddr,
    port: u16,
    dir: AddressType,
}

impl Display for ReportKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let ip = self.ip;
        let port = self.port.clone().to_string();
        write!(f, "{}; {}; {}", ip, port, self.dir)
    }
}

#[derive(Debug)]
struct ReportValue {
    first_timestamp_ms: u64,
    last_timestamp_ms: u64,
    bytes: u64,
    packets_count: usize,
    protocols: HashSet<u8>,
}

impl Display for ReportValue {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let protocols = self
            .protocols
            .iter()
            .map(|p| match p {
                6 => "TCP",
                17 => "UDP",
                _ => "",
            })
            .collect::<Vec<_>>()
            .join(", ");
        write!(
            f,
            "[{}]; {}; {}; {}; {}",
            protocols,
            self.first_timestamp_ms,
            self.last_timestamp_ms,
            self.bytes,
            self.packets_count
        )
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
/// Represents in which state the capture is.
pub enum NasooneState {
    /// The capture is not started and can be configured
    Initial,
    /// The capture is started and can be paused or stopped but not configured.
    Running,
    /// The capture is paused and can be resumed or stopped.
    Paused,
    /// The capture has finished, the user can retrieve stats calling stop.
    Finished,
    /// The capture is stopped and can only return to Initial.
    Stopped,
}

#[derive(Debug)]
/// Represents the pcap statistics about a capture (from <https://docs.rs/pcap/latest/pcap/index.html>.)
pub struct NasooneStats {
    /// Number of packets received
    pub received: u32,
    /// Number of packets dropped because there was no room in the operating system's buffer when
    /// they arrived, because packets weren't being read fast enough
    pub dropped: u32,
    /// Number of packets dropped by the network interface or its driver
    pub if_dropped: u32,
}

impl From<Stat> for NasooneStats {
    fn from(stat: Stat) -> Self {
        Self {
            received: stat.received,
            dropped: stat.dropped,
            if_dropped: stat.if_dropped,
        }
    }
}

/// Abstraction of the pcap capture.
enum NasooneCapture {
    /// The capture is performed on a pcap file.
    FromFile(Capture<Offline>),
    /// The capture is performed on a live network interface.
    FromDevice(Capture<Active>),
}

impl NasooneCapture {
    fn next(&mut self) -> Result<pcap::Packet, pcap::Error> {
        match self {
            NasooneCapture::FromFile(capture) => capture.next(),
            NasooneCapture::FromDevice(capture) => capture.next(),
        }
    }
}

#[derive(Debug)]
/// A network interface that can be used for capturing.
pub struct NetworkInterface {
    /// The name of the network interface.
    name: String,
    /// The optional friendly description of the network interface.
    desc: Option<String>,
}

impl Display for NetworkInterface {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let name = self.desc.clone().unwrap_or_else(|| self.name.clone());
        write!(f, "{}", name)
    }
}

impl NetworkInterface {
    fn new(name: String, desc: Option<String>) -> NetworkInterface {
        NetworkInterface { name, desc }
    }
}

#[derive(Debug)]
/// An error that can occur while using the library.
pub enum NasooneError {
    /// An error from the underlying pcap library.
    PcapError(pcap::Error),
    /// Invalid Nasoone state.
    InvalidState(String),
    /// The specified output path is not valid.
    InvalidOutputPath(String),
    /// The capture type is not set.
    UnsetCapture,
    /// The capture output file is not set.
    UnsetOutput,
    /// The timeout is not valid.
    InvalidTimeout,
    /// The capture has finished by itself.
    CaptureOver,
}

impl Display for NasooneError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NasooneError::PcapError(e) => write!(f, "Pcap error: {}", e),
            NasooneError::InvalidState(s) => write!(f, "Invalid state: {}", s),
            NasooneError::InvalidOutputPath(s) => write!(f, "Invalid output path: {}", s),
            NasooneError::UnsetCapture => write!(f, "Capture is not set"),
            NasooneError::UnsetOutput => write!(f, "Output is not set"),
            NasooneError::InvalidTimeout => write!(f, "Invalid timeout"),
            NasooneError::CaptureOver => write!(f, "Capture is over"),
        }
    }
}

impl Error for NasooneError {}

#[derive(Clone, Eq, PartialEq)]
struct PacketData {
    timestamp_ms: u64,
    data: Vec<u8>,
    bytes: u32,
}

/// A struct for capturing network traffic.
pub struct Nasoone {
    /// The state of the capture.
    state: NasooneState,
    /// The channel sender for sending the state change to the producer thread.
    tx_main_prod: Option<Sender<Command>>,
    /// The periodical timeout after which the output file is updated.
    timeout: u32,
    /// The pcap capture.
    capture: Option<NasooneCapture>,
    /// The path to the output file.
    output: Option<File>,
    /// Producer thread handle.
    producer_handle: Option<thread::JoinHandle<Result<Stat, pcap::Error>>>,
    /// Parser threads handles.
    parser_handles: Vec<thread::JoinHandle<()>>,
    /// Writer thread handle.
    writer_handle: Option<thread::JoinHandle<()>>,
    /// the amount of packets captured in the current session.
    total_packets: Arc<Mutex<usize>>,
}

impl Nasoone {
    pub fn new() -> Self {
        Self {
            state: NasooneState::Initial,
            tx_main_prod: None,
            timeout: 1,
            capture: None,
            output: None,
            producer_handle: None,
            parser_handles: Vec::new(),
            writer_handle: None,
            total_packets: Arc::new(Mutex::new(0)),
        }
    }

    /// Set the capture from a network interface.
    /// It returns an error in the following cases:
    /// - Nasoone is not in the Initial state
    /// - the interface name is not valid
    /// - the capture cannot be activated
    ///
    /// # Arguments
    ///
    /// * `device` - A string slice that holds the name of the interface to capture from.
    ///
    /// # Examples
    ///
    /// Create a nasoone instance and set the capture from the interface "en0"
    /// ```
    /// use nasoone_lib::Nasoone;
    /// let mut nasoone = Nasoone::new();
    /// let _ = nasoone.set_capture_device("en0");
    /// ```
    pub fn set_capture_device(&mut self, device: &str) -> Result<(), NasooneError> {
        match self.state {
            NasooneState::Initial => {
                let capture = Capture::from_device(device).map_err(NasooneError::PcapError)?;
                let capture = capture
                    .promisc(true)
                    .immediate_mode(true)
                    .timeout(200)
                    .open()
                    .map_err(NasooneError::PcapError)?;
                self.capture = Some(NasooneCapture::FromDevice(capture));
                Ok(())
            }
            _ => Err(NasooneError::InvalidState(
                "Nasoone is not in initial state".to_string(),
            )),
        }
    }

    /// Set the capture from a pcap file.
    ///
    /// It returns an error in the following cases:
    /// - Nasoone is not in the Initial state
    /// - the capture file is not valid
    ///
    /// # Arguments
    ///
    /// * `file` - A string slice with the file path.
    ///
    /// # Examples
    ///
    /// Create a nasoone instance and set the capture from the file "capture.pcap":
    /// ```
    /// use nasoone_lib::Nasoone;
    /// let mut nasoone = Nasoone::new();
    /// let  _ = nasoone.set_capture_file("./capture.pcap");
    /// ```
    pub fn set_capture_file(&mut self, file: &str) -> Result<(), NasooneError> {
        match self.state {
            NasooneState::Initial => {
                let capture = Capture::from_file(file).map_err(NasooneError::PcapError)?;
                self.capture = Some(NasooneCapture::FromFile(capture));
                Ok(())
            }
            _ => Err(NasooneError::InvalidState(
                "Nasoone is not in initial state".to_string(),
            )),
        }
    }

    /// Set the timeout in seconds after which the output file is updated.
    ///
    /// The timeout must be greater than 0, it specifies the periodical update of the output file.
    /// So, if the timeout is 1, the output file is updated every second.
    ///
    /// It returns an error in the following cases:
    /// - Nasoone is not in the Initial state
    /// - the timeout is 0
    ///
    /// # Arguments
    ///
    /// * `timeout` - The timeout in seconds.
    ///
    /// # Examples
    ///
    /// Create a nasoone instance and set the timeout to 1 second:
    /// ```
    /// use nasoone_lib::Nasoone;
    /// let mut nasoone = Nasoone::new();
    /// nasoone.set_timeout(1).expect("");
    /// ```
    pub fn set_timeout(&mut self, timeout: u32) -> Result<(), NasooneError> {
        match self.state {
            NasooneState::Initial => {
                if timeout == 0 {
                    Err(NasooneError::InvalidTimeout)
                } else {
                    self.timeout = timeout;
                    Ok(())
                }
            }
            _ => Err(NasooneError::InvalidState(
                "Nasoone is not in initial state".to_string(),
            )),
        }
    }
    /// Set the filter for the capture.
    /// The filter is a [BPF](https://biot.com/capstats/bpf.html) string that is passed to pcap.
    /// Multiple calls to this function will overwrite the previous filter.
    ///
    /// It returns an error in the following cases:
    /// - Nasoone is not in the Initial state
    /// - The capture is not set
    /// - the filter is not valid
    ///
    /// # Arguments
    ///
    /// * `filter` - The filter string in BPF syntax.
    ///
    /// # Examples
    ///
    /// create a nasoone instance and set filter to accept only packets with source port 80 to 88:
    /// ```
    /// use nasoone_lib::Nasoone;
    /// let mut nasoone = Nasoone::new();
    /// nasoone.set_capture_device("en0").expect("");
    /// nasoone.set_filter("src portrange 80-88").expect("");
    /// ```
    pub fn set_filter(&mut self, filter: &str) -> Result<(), NasooneError> {
        match self.state {
            NasooneState::Initial => match self.capture {
                Some(NasooneCapture::FromDevice(ref mut capture)) => {
                    capture
                        .filter(filter, true)
                        .map_err(NasooneError::PcapError)?;
                    Ok(())
                }
                Some(NasooneCapture::FromFile(ref mut capture)) => {
                    capture
                        .filter(filter, true)
                        .map_err(NasooneError::PcapError)?;
                    Ok(())
                }
                None => Err(NasooneError::UnsetCapture),
            },
            _ => Err(NasooneError::InvalidState(
                "Filters can be set only in initial state".to_string(),
            )),
        }
    }
    /// Set the output file.
    /// The output file is a CSV textual report of the capture.
    ///
    /// It returns an error in the following cases:
    /// - Nasoone is not in the Initial state
    /// - the file already exists
    /// - the target directory does not exist
    /// - the file cannot be created
    ///
    /// # Arguments
    ///
    /// * `output_file` - The path of the output file.
    ///
    /// # Examples
    ///
    /// create a nasoone instance and set the output file to "./output.csv":
    /// ```
    /// use nasoone_lib::Nasoone;
    /// let mut nasoone = Nasoone::new();
    /// nasoone.set_output("./output.csv").expect("");
    /// ```
    pub fn set_output(&mut self, output_file: &str) -> Result<(), NasooneError> {
        match self.state {
            NasooneState::Initial => {
                let path = Path::new(output_file);
                if path.exists() {
                    return Err(NasooneError::InvalidOutputPath(
                        "Output file already exists".to_string(),
                    ));
                }
                if path.parent().is_some() && !path.parent().unwrap().exists() {
                    return Err(NasooneError::InvalidOutputPath(
                        "Target directory does not exist".to_string(),
                    ));
                }
                match File::create(path) {
                    Ok(f) => {
                        self.output = Some(f);
                        Ok(())
                    }
                    Err(_) => Err(NasooneError::InvalidOutputPath(
                        "Could not create output file".to_string(),
                    )),
                }
            }
            _ => Err(NasooneError::InvalidState(
                "Output can be set only in initial state".to_string(),
            )),
        }
    }

    /// Start analyzing the network traffic.
    ///
    /// It returns an error in the following cases:
    /// - Nasoone is not in the Initial state
    /// - the capture is not set
    /// - the output is not set
    ///
    /// # Examples
    ///
    /// create a nasoone instance, set the capture and the output file and start the analysis:
    /// ```
    /// use nasoone_lib::Nasoone;
    /// let mut nasoone = Nasoone::new();
    /// nasoone.set_capture_device("en0").expect("");
    /// nasoone.set_output("./output.csv").expect("");
    /// nasoone.start().expect("");
    /// ```
    pub fn start(&mut self) -> Result<(), NasooneError> {
        match self.state {
            NasooneState::Initial => {
                // Create all the threads and start the capture.

                if self.capture.is_none() {
                    return Err(NasooneError::UnsetCapture);
                }
                if self.output.is_none() {
                    return Err(NasooneError::UnsetOutput);
                }

                let (tx_main_prod, rx_main_prod) = crossbeam_channel::unbounded();
                let (tx_prod_parser, rx_prod_parser) = crossbeam_channel::unbounded();
                let (tx_parser_writer, rx_parser_writer) = crossbeam_channel::unbounded();

                let capture = self.capture.take().unwrap();
                self.tx_main_prod = Some(tx_main_prod);
                let total_packets = self.total_packets.clone();
                self.producer_handle = Some(thread::spawn(move || {
                    producer_task(capture, tx_prod_parser, rx_main_prod, total_packets)
                }));

                let num_cpus = num_cpus::get();

                for _ in 0..num_cpus {
                    let rx_prod_parser = rx_prod_parser.clone();
                    let tx_parser_writer = tx_parser_writer.clone();
                    let timeout = self.timeout;
                    self.parser_handles.push(thread::spawn(move || {
                        parser_task(rx_prod_parser, tx_parser_writer, timeout)
                    }));
                }

                let mut output = self.output.take().unwrap();
                let timeout = self.timeout;
                self.writer_handle = Some(thread::spawn(move || {
                    writer_task(rx_parser_writer, &mut output, timeout);
                }));

                self.state = NasooneState::Running;
                Ok(())
            }
            _ => Err(NasooneError::InvalidState(
                "Nasoone is not in initial state".to_string(),
            )),
        }
    }

    /// Pause the analysis of the network traffic.
    ///
    /// If the capture is set from a file, the analysis stop reading the file.
    /// Otherwise, it continues to receive packets from the network interface but it does not analyze them.
    ///
    /// It returns an error in the following cases:
    /// - Nasoone is not in the Running state
    /// - the capture is from a file and the file is over (the analysis is already finished)
    ///
    /// # Examples
    ///
    /// create a nasoone instance, start the analysis and then pause it:
    /// ```
    /// use std::thread::sleep;
    /// use nasoone_lib::Nasoone;
    /// let mut nasoone = Nasoone::new();
    /// nasoone.set_capture_device("en0").expect("");
    /// nasoone.set_output("./output.csv").expect("");
    /// nasoone.start().expect("");
    /// sleep(std::time::Duration::from_secs(5));
    /// nasoone.pause().expect("");
    /// ```
    pub fn pause(&mut self) -> Result<(), NasooneError> {
        match self.state {
            NasooneState::Running => {
                self.state = NasooneState::Paused;
                match self.tx_main_prod.as_ref().unwrap().send(Command::Pause) {
                    Ok(_) => Ok(()),
                    Err(_) => Err(NasooneError::CaptureOver),
                }
            }
            _ => Err(NasooneError::InvalidState(
                "Nasoone is not running".to_string(),
            )),
        }
    }

    /// Resume the analysis if it was paused.
    ///
    /// It returns an error in the following cases:
    /// - Nasoone is not in the Paused state
    /// - the capture is from a file and the file is over (the analysis is already finished)
    ///
    /// # Examples
    ///
    /// create a nasoone instance, start the analysis, pause it and then resume it:
    /// ```
    /// use nasoone_lib::Nasoone;
    /// let mut nasoone = Nasoone::new();
    /// nasoone.set_capture_device("en0").expect("");
    /// nasoone.set_output("./output.csv").expect("");
    /// nasoone.start().expect("");
    /// nasoone.pause().expect("");
    /// nasoone.resume().expect("");
    /// ```
    pub fn resume(&mut self) -> Result<(), NasooneError> {
        match self.state {
            NasooneState::Paused => {
                self.state = NasooneState::Running;
                match self.tx_main_prod.as_ref().unwrap().send(Command::Resume) {
                    Ok(_) => Ok(()),
                    Err(_) => Err(NasooneError::CaptureOver),
                }
            }
            _ => Err(NasooneError::InvalidState(
                "Nasoone is not paused".to_string(),
            )),
        }
    }

    /// Stop the capture if it is running or paused. It will wait for the threads to finish,
    /// so it could take some time (up to 200-250ms).
    ///
    /// It returns the statistics of the capture only if the capture is from a network interface.
    /// Otherwise, it will return None.
    ///
    /// It returns an error in the following cases:
    /// - Nasoone is not in the Running, Finished or Paused state
    ///
    /// # Examples
    ///
    /// create a nasoone instance, start the analysis and then stop it:
    /// ```
    /// use nasoone_lib::Nasoone;
    /// let mut nasoone = Nasoone::new();
    /// nasoone.set_capture_device("en0").expect("");
    /// nasoone.set_output("./output.csv").expect("");
    /// nasoone.start().expect("");
    /// let stats = nasoone.stop().expect("");
    /// ```
    pub fn stop(&mut self) -> Result<Option<NasooneStats>, NasooneError> {
        match self.state {
            NasooneState::Running | NasooneState::Paused | NasooneState::Finished => {
                self.state = NasooneState::Stopped;
                let _ = self.tx_main_prod.as_ref().unwrap().send(Command::Stop); // ignore a possible error that would mean that the producer thread is already stopped
                let stat = self.producer_handle.take().unwrap().join().unwrap();
                for handle in self.parser_handles.drain(..) {
                    handle.join().unwrap();
                }
                self.writer_handle.take().unwrap().join().unwrap();
                if stat.is_err() {
                    return Ok(None);
                }
                Ok(Some(NasooneStats::from(stat.unwrap())))
            }
            _ => Err(NasooneError::InvalidState(
                "Nasoone is not running".to_string(),
            )),
        }
    }

    /// Get the total amount of packet received by the capture.
    ///
    /// # Examples
    ///
    /// Create a nasoone instance, start the analysis and then get the total amount of packet received:
    /// ```
    /// use std::thread::sleep;
    /// use nasoone_lib::{Nasoone, NasooneState};
    /// let mut nasoone = Nasoone::new();
    /// nasoone.set_capture_device("en0").expect("");
    /// nasoone.set_output("./output.csv").expect("");
    /// nasoone.start().expect("");
    /// sleep(std::time::Duration::from_secs(5));
    /// assert!(nasoone.get_total_packets() > 0);
    /// ```
    pub fn get_total_packets(&mut self) -> usize {
        *self.total_packets.lock().unwrap()
    }

    /// Get the current state of the capture.
    ///
    /// # Examples
    ///
    /// Create a nasoone instance, start the analysis, pause it and ask for the state:
    /// ```
    /// use nasoone_lib::{Nasoone, NasooneState};
    /// let mut nasoone = Nasoone::new();
    /// nasoone.set_capture_device("en0").expect("");
    /// nasoone.set_output("./output.csv").expect("");
    /// nasoone.start().expect("");
    /// nasoone.pause().expect("");
    /// assert_eq!(nasoone.get_state(), NasooneState::Paused);
    /// ```
    pub fn get_state(&mut self) -> NasooneState {
        // control if the capture has finished by itself
        if self.producer_handle.as_ref().is_some()
            && self.producer_handle.as_ref().unwrap().is_finished()
        {
            self.state = NasooneState::Finished;
        }
        self.state.clone()
    }

    /// Get the list of available network interfaces.
    ///
    /// It could return underlined errors from the pcap library.
    ///
    /// # Examples
    /// ```
    /// use nasoone_lib::Nasoone;
    /// let interfaces = Nasoone::list_devices().expect("");
    /// ```
    pub fn list_devices() -> Result<Vec<NetworkInterface>, NasooneError> {
        let devices = Device::list()
            .map_err(NasooneError::PcapError)?
            .into_iter()
            .map(|d| NetworkInterface::new(d.name, d.desc))
            .collect();
        Ok(devices)
    }

    /// Get the name of the default network interface.
    pub fn get_default_device_name() -> Result<String, NasooneError> {
        let device = Device::lookup().map_err(NasooneError::PcapError)?;
        Ok(device.name)
    }
}

impl Drop for Nasoone {
    fn drop(&mut self) {
        if self.state != NasooneState::Stopped {
            // try to stop the capture
            let _ = self.stop();
        }
    }
}

impl Default for Nasoone {
    fn default() -> Self {
        Self::new()
    }
}
