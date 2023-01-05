use std::{str, path::PathBuf, fs::{self, File}, io::{Write, self, Read, Seek, SeekFrom}};

use ecies::{encrypt, decrypt, utils::generate_keypair};

use crate::storage::entries::EntryOperationDto;

use super::registry_header::RegistryHeader;

pub struct RegistryRepository {
    file: File,
    pub name: String,
    public_key: Vec<u8>,
    private_key: Option<Vec<u8>>,
}

impl RegistryRepository {
    pub fn init(path: &PathBuf, name: &str, password: &str) -> Result<Self, io::Error> {
        let (private_key, public_key) = generate_keypair();
        let public_key = public_key.serialize_compressed().to_vec();
        let private_key = private_key.serialize().to_vec();

        fs::create_dir_all(path)?;
    
        let file_path = path.join(FILE_NAME);

        if file_path.exists() {
            panic!("Can not initialize existing registry");
        }
    
        let encrypted_private_key = simplecrypt::encrypt(&private_key, password.as_bytes());
    
        let name: String = name.chars().take(64).collect();
    
        let mut name_bytes = [0u8; 256];
        let bytes = name.as_bytes();
        name_bytes[..bytes.len()].clone_from_slice(bytes);
    
        let header = RegistryHeader {
            version: 1,
            name: name_bytes,
            key_type: 1,
            public_key_size: public_key.len() as i32,
            private_key_size: encrypted_private_key.len() as i32,
        };
    
        let mut file = File::create(file_path)?;
        header.write(&mut file)?;
        file.write(&public_key)?;
        file.write(&encrypted_private_key)?;

        let result = Self {
            file,
            name,
            public_key,
            private_key: Some(private_key),
        };

        Ok(result)
    }

    pub fn open(path: &PathBuf) -> Result<Self, io::Error> {
        let mut file = File::options()
            .read(true)
            .write(true)
            .open(path.join(FILE_NAME))?;

        let header = RegistryHeader::read(&mut file)?;

        let mut public_key = vec![0; header.public_key_size as usize];
        file.read_exact(public_key.as_mut_slice())?;

        file.seek(SeekFrom::Current(header.private_key_size as i64))?;
        
        let result = Self {
            file,
            name: String::from(str::from_utf8(&header.name).unwrap()),
            public_key,
            private_key: None,
        };

        Ok(result)
    }

    pub fn open_decrypt(path: &PathBuf, password: &str) -> Result<Self, io::Error> {
        let mut file = File::options()
            .read(true)
            .write(true)
            .open(path.join(FILE_NAME))?;

        let header = RegistryHeader::read(&mut file)?;

        let mut public_key = vec![0; header.public_key_size as usize];
        file.read_exact(public_key.as_mut_slice())?;

        let mut private_key = vec![0; header.private_key_size as usize];
        file.read_exact(private_key.as_mut_slice())?;
        
        let result = Self {
            file,
            name: String::from(str::from_utf8(&header.name).unwrap()),
            public_key,
            private_key: Some(simplecrypt::decrypt(&private_key, password.as_bytes()).unwrap()),
        };

        Ok(result)
    }

    pub fn write_operation(&mut self, operation: &EntryOperationDto) -> Result<(), io::Error> {
        match operation {
            EntryOperationDto::Add { hash, name, description, secret } => {
                self.file.write(&1i32.to_le_bytes())?;
                self.file.write(hash)?;

                write_string(&mut self.file, Some(name))?;
                write_string(&mut self.file, Some(description))?;
                write_bytes(&mut self.file, Some(secret))?;
            },
            EntryOperationDto::Set { hash, src_name, dst_name, dst_description, dst_secret } => {
                self.file.write(&2i32.to_le_bytes())?;
                self.file.write(hash)?;

                write_string(&mut self.file, Some(src_name))?;
                write_string(&mut self.file, dst_name.as_ref().map(|o| o.as_str()))?;
                write_string(&mut self.file, dst_description.as_ref().map(|o| o.as_str()))?;
                write_bytes(&mut self.file, dst_secret.as_ref().map(|o| o.as_slice()))?;
            },
            EntryOperationDto::Del { hash, name } => {
                self.file.write(&3i32.to_le_bytes())?;
                self.file.write(hash)?;

                write_string(&mut self.file, Some(name))?;
            },
        }

        Ok(())
    }

    pub fn read_operation(&mut self) -> Result<Option<EntryOperationDto>, io::Error> {
        if let Some(op_code) = read_i32_option(&mut self.file)? {
            let result = match op_code {
                1 => {
                    EntryOperationDto::Add { 
                        hash: read_bytes_array::<32>(&mut self.file)?, 
                        name: read_string(&mut self.file)?.unwrap(), 
                        description: read_string(&mut self.file)?.unwrap(), 
                        secret: read_bytes(&mut self.file)?.unwrap(),
                    }
                },
                2 => {
                    EntryOperationDto::Set { 
                        hash: read_bytes_array::<32>(&mut self.file)?, 
                        src_name: read_string(&mut self.file)?.unwrap(), 
                        dst_name: read_string(&mut self.file)?, 
                        dst_description: read_string(&mut self.file)?, 
                        dst_secret: read_bytes(&mut self.file)?,
                    }
                },
                3 => {
                    EntryOperationDto::Del { 
                        hash: read_bytes_array::<32>(&mut self.file)?, 
                        name: read_string(&mut self.file)?.unwrap(),
                    }
                },
                _ => panic!("Invalid entry operation code"),
            };
    
            Ok(Some(result))
        }
        else {
            Ok(None)
        }
    }


    // pub fn decrypted(&self) -> bool {
    //     self.private_key.is_some()
    // }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        encrypt(&self.public_key, data).unwrap()
    }

    pub fn decrypt(&self, data: &[u8]) -> Option<Vec<u8>> {
        if let Some(private_key) = self.private_key.as_ref() {
            match decrypt(private_key, data) {
                Ok(result) => {
                    if data.len() > 0 && result.len() == 0 {
                        None
                    }
                    else {
                        Some(result)
                    }
                },
                Err(_) => None,
            }
        }
        else {
            None
        }
    }
}

const FILE_NAME: &str = "registry";

fn write_i32(file: &mut File, data: i32) -> Result<(), io::Error> {
    file.write(&data.to_le_bytes())?;
    Ok(())
}

fn read_i32_option(file: &mut File) -> Result<Option<i32>, io::Error> {
    let mut buffer = [0u8; 4];
    if file.read(buffer.as_mut_slice())? != 4 {
        return Ok(None);
    }
    Ok(Some(i32::from_le_bytes(buffer)))
}


fn read_i32(file: &mut File) -> Result<i32, io::Error> {
    let mut buffer = [0u8; 4];
    file.read_exact(buffer.as_mut_slice())?;
    Ok(i32::from_le_bytes(buffer))
}

fn write_bytes(file: &mut File, data: Option<&[u8]>) -> Result<(), io::Error> {
    if let Some(data) = data {
        write_i32(file, data.len() as i32)?;
        file.write(data)?;
    }
    else {
        write_i32(file, -1)?;
    }

    Ok(())
}

fn read_bytes(file: &mut File) -> Result<Option<Vec<u8>>, io::Error> {
    let size = read_i32(file)?;
    if size == -1 {
        return Ok(None);
    }

    let mut data = vec![0; size as usize];
    file.read_exact(data.as_mut_slice())?;

    Ok(Some(data))
}

fn read_bytes_array<const COUNT: usize>(file: &mut File) -> Result<[u8; COUNT], io::Error> {
    let mut buffer = [0u8; COUNT];
    file.read_exact(buffer.as_mut_slice())?;
    return Ok(buffer);
}

fn write_string(file: &mut File, data: Option<&str>) -> Result<(), io::Error> {
    write_bytes(file, data.map(|x| x.as_bytes()))
}

fn read_string(file: &mut File) -> Result<Option<String>, io::Error> {
    read_bytes(file).map(|r| r.map(|o| String::from_utf8(o).unwrap()))
}
