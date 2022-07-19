//! Nasoone-lib is a library for the NASOONE project.
//! It provides a struct for analyzing network traffic using [pcap](https://docs.rs/pcap/latest/pcap/index.html).

pub mod filter;

use crate::filter::Filter;
use pcap::{Active, Capture, Device, Offline};

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
    UnsetCapture,
}

pub struct Nasoone {
    state: NasooneState,
    filter: Option<Filter>,
    timeout: u64,
    capture: NasooneCapture,
    output: String,
}

impl Nasoone {
    pub fn new() -> Self {
        Self {
            state: NasooneState::Initial,
            filter: None,
            timeout: 1,
            capture: NasooneCapture::Unset,
            output: String::new(),
        }
    }
    pub fn set_capture_device(&mut self, device: &str) -> Result<(), NasooneError> {
        let capture = Capture::from_device(device).map_err(NasooneError::PcapError)?;
        let capture = capture
            .promisc(true)
            .immediate_mode(true)
            .open()
            .map_err(NasooneError::PcapError)?;
        self.capture = NasooneCapture::FromDevice(capture);
        Ok(())
    }
    pub fn set_capture_file(&mut self, file: &str) -> Result<(), NasooneError> {
        let capture = Capture::from_file(file).map_err(NasooneError::PcapError)?;
        self.capture = NasooneCapture::FromFile(capture);
        Ok(())
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
