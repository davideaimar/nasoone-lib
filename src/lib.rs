//! Nasoone-lib is a library for the NASOONE project.
//! It provides a struct for analyzing network data using [pcap](https://docs.rs/pcap/latest/pcap/index.html).

use std::marker::PhantomData;

pub struct Initial{}
pub struct Running{}
pub struct Paused{}
pub struct Stopped{}

pub struct Nasoone<State> {
    state: PhantomData<State>
}

impl<Src> Nasoone<Src> {
    fn transition<Dest>(self) -> Nasoone<Dest> {
        let Nasoone { state: _} = self;
        Nasoone {  state: PhantomData }
    }
}

impl Nasoone<Initial> {
    pub fn from_file(_path: &str) -> Result<Nasoone<Initial>, ()> {
        Ok(Nasoone { state: PhantomData })
    }
    pub fn from_device(_device: &str) -> Result<Nasoone<Initial>, ()> {
        Ok(Nasoone { state: PhantomData })
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
    use crate::Nasoone;

    #[test]
    fn it_compiles() {
        let _naso = Nasoone::from_device("en0").unwrap();
        let _naso = _naso.start().unwrap();
        let _naso = _naso.pause().unwrap();
        let _naso = _naso.resume().unwrap();
        let _naso = _naso.pause().unwrap();
        let _naso = _naso.stop().unwrap();
    }
}
