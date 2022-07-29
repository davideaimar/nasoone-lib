//! Nasoone-lib is a library for the NASOONE project.
//! It provides a struct for analyzing network traffic using [pcap](https://docs.rs/pcap/latest/pcap/index.html).

mod parser;
mod producer;
mod writer;

use crate::parser::parser_task;
use crate::producer::producer_task;
use crate::writer::writer_task;
use pcap::{Active, Capture, Device, Offline};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

#[derive(PartialEq, Debug)]
/// Represents in which state the capture is.
pub enum NasooneState {
    /// The capture is not started and can be configured
    Initial,
    /// The capture is started and can be paused or stopped but not configured.
    Running,
    /// The capture is paused and can be resumed or stopped.
    Paused,
    /// The capture is stopped and can only return to Initial.
    Stopped,
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
}

impl Display for NasooneError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NasooneError::PcapError(e) => write!(f, "Pcap error: {}", e),
            NasooneError::InvalidState(s) => write!(f, "Invalid state: {}", s),
            NasooneError::InvalidOutputPath(s) => write!(f, "Invalid output path: {}", s),
            NasooneError::UnsetCapture => write!(f, "Capture is not set"),
            NasooneError::UnsetOutput => write!(f, "Output is not set"),
        }
    }
}

impl Error for NasooneError {}

/// A struct for capturing network traffic.
pub struct Nasoone {
    /// The state of the capture.
    state: Arc<(Condvar, Mutex<NasooneState>)>,
    /// The periodical timeout after which the output file is updated.
    timeout: u32,
    /// The pcap capture.
    capture: Option<NasooneCapture>,
    /// The path to the output file.
    output: Option<File>,
}

struct PacketData {
    timestamp: u64,
    data: Vec<u8>,
    bytes: u32,
}

impl Nasoone {
    pub fn new() -> Self {
        Self {
            state: Arc::new((Condvar::new(), Mutex::new(NasooneState::Initial))),
            timeout: 1,
            capture: None,
            output: None,
        }
    }
    /// Set the capture from a network interface.
    pub fn set_capture_device(&mut self, device: &str) -> Result<(), NasooneError> {
        match *self.state.1.lock().unwrap() {
            NasooneState::Initial => {
                let capture = Capture::from_device(device).map_err(NasooneError::PcapError)?;
                let capture = capture
                    .promisc(true)
                    .immediate_mode(true)
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
    pub fn set_capture_file(&mut self, file: &str) -> Result<(), NasooneError> {
        match *self.state.1.lock().unwrap() {
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
    /// Set the update timeout.
    pub fn set_timeout(&mut self, timeout: u32) -> Result<(), NasooneError> {
        match *self.state.1.lock().unwrap() {
            NasooneState::Initial => {
                self.timeout = timeout;
                Ok(())
            }
            _ => Err(NasooneError::InvalidState(
                "Nasoone is not in initial state".to_string(),
            )),
        }
    }
    /// Set the filter for the capture.
    /// The filter is a [BPF](https://biot.com/capstats/bpf.html) string that is passed to pcap.
    /// Multiple calls to this function will overwrite the previous filter.
    pub fn set_filter(&mut self, filter: &str) -> Result<(), NasooneError> {
        match *self.state.1.lock().unwrap() {
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
    pub fn set_output(&mut self, output_file: &str) -> Result<(), NasooneError> {
        match *self.state.1.lock().unwrap() {
            NasooneState::Initial => {
                let path = Path::new(output_file);
                if path.exists() {
                    return Err(NasooneError::InvalidOutputPath(
                        "Output file already exists".to_string(),
                    ));
                }
                if path.parent().is_some() && !path.parent().unwrap().exists() {
                    return Err(NasooneError::InvalidOutputPath(
                        "Parent directory of output file does not exist".to_string(),
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

    /// Start the capture.
    pub fn start(&mut self) -> Result<(), NasooneError> {
        let mut state = self.state.1.lock().unwrap();
        match *state {
            NasooneState::Initial => {
                // Create all the threads and start the capture.

                if self.capture.is_none() {
                    return Err(NasooneError::UnsetCapture);
                }
                if self.output.is_none() {
                    return Err(NasooneError::UnsetOutput);
                }

                let (tx_prod_parser, rx_prod_parser) = crossbeam_channel::unbounded();

                let capture = self.capture.take().unwrap();
                let state_c = self.state.clone();
                thread::spawn(move || producer_task(capture, tx_prod_parser, state_c));

                let num_cpus = num_cpus::get();

                for _ in 0..num_cpus {
                    let rx_prod_parser = rx_prod_parser.clone();
                    let timeout = self.timeout;
                    thread::spawn(move || parser_task(rx_prod_parser, timeout));
                }

                let output = self.output.take().unwrap();
                thread::spawn(move || writer_task(output));

                *state = NasooneState::Running;
                Ok(())
            }
            _ => Err(NasooneError::InvalidState(
                "Nasoone is already running".to_string(),
            )),
        }
    }

    /// Pause the capture if it is running.
    pub fn pause(&mut self) -> Result<(), NasooneError> {
        let mut state = self.state.1.lock().unwrap();
        match *state {
            NasooneState::Running => {
                *state = NasooneState::Paused;
                self.state.0.notify_one();
                Ok(())
            }
            _ => Err(NasooneError::InvalidState(
                "Nasoone is not running".to_string(),
            )),
        }
    }

    /// Resume the capture if it is paused.
    pub fn resume(&mut self) -> Result<(), NasooneError> {
        let mut state = self.state.1.lock().unwrap();
        match *state {
            NasooneState::Paused => {
                *state = NasooneState::Running;
                self.state.0.notify_one();
                Ok(())
            }
            _ => Err(NasooneError::InvalidState(
                "Nasoone is not running".to_string(),
            )),
        }
    }

    /// Stop the capture if it is running or paused.
    pub fn stop(&mut self) -> Result<(), NasooneError> {
        let mut state = self.state.1.lock().unwrap();
        match *state {
            NasooneState::Running | NasooneState::Paused => {
                *state = NasooneState::Stopped;
                self.state.0.notify_one();
                Ok(())
            }
            _ => Err(NasooneError::InvalidState(
                "Nasoone is not running".to_string(),
            )),
        }
    }

    /// Get the current state of the capture.
    pub fn get_state(&self) -> NasooneState {
        match *self.state.1.lock().unwrap() {
            NasooneState::Initial => NasooneState::Initial,
            NasooneState::Running => NasooneState::Running,
            NasooneState::Paused => NasooneState::Paused,
            NasooneState::Stopped => NasooneState::Stopped,
        }
    }

    /// Get the list of available network interfaces.
    pub fn list_devices() -> Result<Vec<NetworkInterface>, NasooneError> {
        let devices = Device::list().map_err(NasooneError::PcapError)?;
        let devices = devices
            .into_iter()
            .map(|d| NetworkInterface::new(d.name, d.desc))
            .collect();
        Ok(devices)
    }
}

impl Default for Nasoone {
    fn default() -> Self {
        Self::new()
    }
}
