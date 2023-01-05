use std::{collections::HashMap, io};

use sha3::{Digest, Sha3_256};

use crate::storage::{registries::RegistryRepository, entries::EntryOperationDto};

use super::EntryModel;

pub struct EntryService {
    registry_repository: RegistryRepository,
    last_hash: [u8; 32],
    pub entries: HashMap<String, EntryModel>,
}

impl EntryService {
    pub fn new(registry_repository: RegistryRepository) -> Result<Self, io::Error> {
        let mut result = Self {
            registry_repository,
            last_hash: [0u8; 32],
            entries: HashMap::new(),
        };

        while let Some(entry_change) = result.registry_repository.read_operation()? {
            match entry_change {
                EntryOperationDto::Add { hash, name, description, secret } => {
                    result.last_hash = hash;

                    let model = EntryModel { 
                        description, 
                        secret,
                    };

                    if result.entries.insert(name, model).is_some() {
                        panic!("Registry is malformed. Can not add existing entry.");
                    }
                },
                EntryOperationDto::Set { hash, src_name, dst_name, dst_description, dst_secret } => {
                    result.last_hash = hash;

                    if let Some(current) = result.entries.remove(&src_name) {
                        let model = EntryModel { 
                            description: dst_description.unwrap_or(current.description), 
                            secret: dst_secret.unwrap_or(current.secret),
                        };
    
                        result.entries.insert(dst_name.unwrap_or(src_name), model);
                    }
                    else {
                        panic!("Registry is malformed. Can not set non existing entry.");
                    }
                },
                EntryOperationDto::Del { hash, name } => {
                    result.last_hash = hash;

                    if result.entries.remove(&name).is_some() {
                        panic!("Registry is malformed. Can not del non existing entry.");
                    }
                },
            }
        }

        Ok(result)
    }

    pub fn registry_name(&self) -> &str {
        &self.registry_repository.name
    }

    pub fn decrypt_secret(&self, secret: &Vec<u8>) -> Option<Vec<u8>> {
        self.registry_repository.decrypt(&secret)
    }

    pub fn add(&mut self, name: String, description: String, secret: Vec<u8>) -> Result<(), io::Error> {
        if self.entries.contains_key(&name) {
            panic!("Can not add existing entry")
        }
        
        let secret = self.registry_repository.encrypt(&secret);

        let entry = EntryModel {
            description,
            secret,
        };

        let mut hasher = Sha3_256::new();
        hasher.update(&self.last_hash);
        hasher.update(&1i32.to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update(entry.description.as_bytes());
        hasher.update(&entry.secret);
        self.last_hash = hasher.finalize().into();

        let entry_operation = EntryOperationDto::Add { 
            hash: self.last_hash, 
            name: name.clone(), 
            description: entry.description.clone(), 
            secret: entry.secret.clone(),
        };

        self.entries.insert(name, entry);

        self.registry_repository.write_operation(&entry_operation)?;

        Ok(())
    }

    pub fn set(
        &mut self, 
        src_name: String, 
        dst_name: Option<String>, 
        dst_description: Option<String>, 
        dst_secret: Option<Vec<u8>>,
    ) -> Result<(), io::Error> {
        let current = self.entries.remove(&src_name);
        
        if let Some(current) = current {
            let dst_secret = dst_secret.map(|s| self.registry_repository.encrypt(&s));
    
            let mut hasher = Sha3_256::new();
            hasher.update(&self.last_hash);
            hasher.update(&2i32.to_le_bytes());
            hasher.update(src_name.as_bytes());
            if let Some(dst_name) = &dst_name {
                hasher.update(dst_name.as_bytes());
            }
            if let Some(dst_description) = &dst_description {
                hasher.update(dst_description.as_bytes());
            }
            if let Some(dst_secret) = &dst_secret {
                hasher.update(&dst_secret);
            }
            self.last_hash = hasher.finalize().into();
    
            let entry_operation = EntryOperationDto::Set { 
                hash: self.last_hash, 
                src_name: src_name.clone(), 
                dst_name: dst_name.clone(), 
                dst_description: dst_description.clone(), 
                dst_secret: dst_secret.clone(),
            };

            let new_entry = EntryModel {
                description: dst_description.unwrap_or(current.description),
                secret: dst_secret.unwrap_or(current.secret),
            };
    
            self.entries.insert(dst_name.unwrap_or(src_name), new_entry);
    
            self.registry_repository.write_operation(&entry_operation)?;
    
            Ok(())
        }
        else {
            panic!("Can not set non existing entry")
        }    
    }

    pub fn del(&mut self, name: String) -> Result<(), io::Error> {
        if !self.entries.remove(&name).is_some() {
            panic!("Can not del non existing entry")
        }
        
        let mut hasher = Sha3_256::new();
        hasher.update(&self.last_hash);
        hasher.update(&3i32.to_le_bytes());
        hasher.update(name.as_bytes());
        self.last_hash = hasher.finalize().into();

        let entry_operation = EntryOperationDto::Del { 
            hash: self.last_hash, 
            name: name.clone(), 
        };

        self.registry_repository.write_operation(&entry_operation)?;

        Ok(())
    }
}