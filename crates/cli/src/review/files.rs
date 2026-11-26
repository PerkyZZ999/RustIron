use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use super::Failure;

pub(super) fn read(path: &Path, limit: usize) -> Result<Vec<u8>, Failure> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(
            rustix::fs::OFlags::NOFOLLOW.bits() as i32 | rustix::fs::OFlags::NONBLOCK.bits() as i32,
        )
        .open(path)
        .map_err(|_| Failure::input())?;
    if !file.metadata().map_err(|_| Failure::input())?.is_file() {
        return Err(Failure::input());
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::input())?;
    if bytes.len() > limit {
        return Err(Failure::input());
    }
    Ok(bytes)
}

pub(super) struct Scratch {
    path: PathBuf,
    names: Vec<&'static str>,
}

impl Scratch {
    pub fn new() -> Result<Self, Failure> {
        let mut random = [0; 16];
        rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())
            .map_err(|_| Failure::dependency())?;
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = PathBuf::from(format!("/tmp/rustiron-review-{suffix}"));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|_| Failure::dependency())?;
        Ok(Self {
            path,
            names: Vec::new(),
        })
    }

    pub fn write(&mut self, name: &'static str, bytes: &[u8]) -> Result<PathBuf, Failure> {
        let path = self.path.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|_| Failure::dependency())?;
        self.names.push(name);
        file.write_all(bytes).map_err(|_| Failure::dependency())?;
        Ok(path)
    }

    pub fn close(self) -> Result<(), Failure> {
        for name in &self.names {
            fs::remove_file(self.path.join(name)).map_err(|_| Failure::dependency())?;
        }
        fs::remove_dir(&self.path).map_err(|_| Failure::dependency())
    }
}

pub(super) fn input_file(path: &Path) -> Result<File, Failure> {
    File::open(path).map_err(|_| Failure::dependency())
}
