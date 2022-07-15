//! Nasoone-lib is a library for the NASOONE project.
//! It provides a struct for analyzing network data using [pcap](https://docs.rs/pcap/latest/pcap/index.html).

mod filter;

use std::marker::PhantomData;
use crate::filter::Filter;

pub struct Initial{}
pub struct Running{}
pub struct Paused{}
pub struct Stopped{}

pub struct Nasoone<State> {
    state: PhantomData<State>,
    filter: Option<Filter>,
}

impl<Src> Nasoone<Src> {
    fn transition<Dest>(self) -> Nasoone<Dest> {
        let Nasoone { filter, state: _} = self;
        Nasoone { filter, state: PhantomData }
    }
}

impl Nasoone<Initial> {
    pub fn from_file(_path: &str) -> Result<Nasoone<Initial>, ()> {
        Ok(Nasoone { state: PhantomData, filter: None })
    }
    pub fn from_device(_device: &str) -> Result<Nasoone<Initial>, ()> {
        Ok(Nasoone { state: PhantomData, filter: None })
    }
    pub fn set_filter(&mut self, filter: Filter) {
        self.filter = Some(filter);
    }
    pub fn start(self) -> Result<Nasoone<Running>, ()> {
        // TODO: implement start
        Ok(self.transition())
    }
}

impl Nasoone<Running> {
    pub fn pause(self) -> Result<Nasoone<Paused>, ()> {
        // TODO: implement pause
        Ok(self.transition())
    }
}

impl Nasoone<Paused> {
    pub fn stop(self) -> Result<Nasoone<Stopped>, ()> {
        // TODO: implement stop
        Ok(self.transition())
    }
    pub fn resume(self) -> Result<Nasoone<Running>, ()> {
        // TODO: implement resume
        Ok(self.transition())
    }
}

impl Nasoone<Stopped> {
    pub fn reset(self) -> Result<Nasoone<Initial>, ()> {
        // TODO: implement capture reset
        Ok(self.transition())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use crate::{Filter, Nasoone};

    #[test]
    fn it_compiles() {
        let mut naso = Nasoone::from_device("en0").unwrap();
        let mut filter = Filter::new();
        filter.add_port(80);
        filter.add_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        filter.add_ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
        naso.set_filter(filter);
        let naso = naso.start().unwrap();
        let naso = naso.pause().unwrap();
        let naso = naso.resume().unwrap();
        let naso = naso.pause().unwrap();
        naso.stop().unwrap();
    }
}
