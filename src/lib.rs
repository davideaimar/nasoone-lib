//! Nasoone-lib is a library for the NASOONE project.
//! It provides a struct for analyzing network traffic using [pcap](https://docs.rs/pcap/latest/pcap/index.html).

pub mod filter;

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::File;
use crate::filter::Filter;
use pcap::{Active, Capture, Device, Offline};
use std::path::Path;

enum NasooneState {
    Initial,
    Running,
    Paused,
    Stopped,
}

enum NasooneCapture {
    FromFile(Capture<Offline>),
    FromDevice(Capture<Active>),
    Unset,
}

#[derive(Debug)]
pub enum NasooneError {
    PcapError(pcap::Error),
    InvalidState(String),
    InvalidOutputPath(String),
    UnsetCapture,
}

impl Display for NasooneError{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NasooneError::PcapError(e) => write!(f, "Pcap error: {}", e),
            NasooneError::InvalidState(s) => write!(f, "Invalid state: {}", s),
            NasooneError::InvalidOutputPath(s) => write!(f, "Invalid output path: {}", s),
            NasooneError::UnsetCapture => write!(f, "Capture is not set"),
        }
    }
}

impl Error for NasooneError {}

pub struct Nasoone {
    state: NasooneState,
    filter: Option<Filter>,
    timeout: u64,
    capture: NasooneCapture,
    output: Option<File>,
}

impl Nasoone {
    pub fn new() -> Self {
        Self {
            state: NasooneState::Initial,
            filter: None,
            timeout: 1,
            capture: NasooneCapture::Unset,
            output: None,
        }
    }
    pub fn set_capture_device(&mut self, device: &str) -> Result<(), NasooneError> {
        match self.state {
            NasooneState::Initial => {
                let capture = Capture::from_device(device).map_err(NasooneError::PcapError)?;
                let capture = capture
                    .promisc(true)
                    .immediate_mode(true)
                    .open()
                    .map_err(NasooneError::PcapError)?;
                self.capture = NasooneCapture::FromDevice(capture);
                Ok(())
            }
            _ => Err(NasooneError::InvalidState(
                "Nasoone is already running".to_string(),
            )),
        }
    }
    pub fn set_capture_file(&mut self, file: &str) -> Result<(), NasooneError> {
        match self.state {
            NasooneState::Initial => {
                let capture = Capture::from_file(file).map_err(NasooneError::PcapError)?;
                self.capture = NasooneCapture::FromFile(capture);
                Ok(())
            }
            _ => Err(NasooneError::InvalidState(
                "Nasoone is already running".to_string(),
            )),
        }
    }
    pub fn set_filter(&mut self, filter: Filter) -> Result<(), NasooneError> {
        match self.state {
            NasooneState::Initial => {
                self.filter = Some(filter);
                Ok(())
            }
            _ => Err(NasooneError::InvalidState(
                "Filters can be set only in initial state".to_string(),
            )),
        }
    }
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
                        "Output file parent directory does not exist".to_string(),
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
    pub fn start(&mut self) -> Result<(), NasooneError> {
        match self.state {
            NasooneState::Initial => {
                self.state = NasooneState::Running;
                // TODO: manage capture
                let _remove_warning = &self.output;
                let _remove_warning = &self.timeout;
                Ok(())
            }
            _ => Err(NasooneError::InvalidState(
                "Nasoone is already running".to_string(),
            )),
        }
    }
    pub fn pause(&mut self) -> Result<(), NasooneError> {
        match self.state {
            NasooneState::Running => {
                self.state = NasooneState::Paused;
                // TODO: manage pause
                Ok(())
            }
            _ => Err(NasooneError::InvalidState(
                "Nasoone is not running".to_string(),
            )),
        }
    }
    pub fn stop(&mut self) -> Result<(), NasooneError> {
        match self.state {
            NasooneState::Running | NasooneState::Paused => {
                self.state = NasooneState::Stopped;
                // TODO: manage stop
                Ok(())
            }
            _ => Err(NasooneError::InvalidState(
                "Nasoone is not running".to_string(),
            )),
        }
    }
    pub fn list_devices() -> Result<Vec<String>, NasooneError> {
        let devices = Device::list().map_err(NasooneError::PcapError)?;
        let mut device_names = Vec::new();
        for device in devices {
            device_names.push(device.name.to_string());
        }
        Ok(device_names)
    }
}

impl Default for Nasoone {
    fn default() -> Self {
        Self::new()
    }
}
