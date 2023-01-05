use std::{fs::File, io::{Write, self, Read}};

pub struct RegistryHeader {
    pub version: i32,
    pub name: [u8; 256],
    pub key_type: i32,
    pub public_key_size: i32,
    pub private_key_size: i32,
}

impl RegistryHeader {
    pub fn read(file: &mut File) -> Result<Self, io::Error> {
        let mut u32_buffer = [0u8; 4];
        let mut name = [0u8; 256];

        file.read_exact(u32_buffer.as_mut_slice())?;
        let version = i32::from_le_bytes(u32_buffer);

        file.read_exact(name.as_mut_slice())?;

        file.read_exact(u32_buffer.as_mut_slice())?;
        let key_type = i32::from_le_bytes(u32_buffer);

        file.read_exact(u32_buffer.as_mut_slice())?;
        let public_key_size = i32::from_le_bytes(u32_buffer);

        file.read_exact(u32_buffer.as_mut_slice())?;
        let private_key_size = i32::from_le_bytes(u32_buffer);

        let result = Self {
            version,
            name,
            key_type,
            public_key_size,
            private_key_size,
        };
        
        Ok(result)
    }

    pub fn write(&self, file: &mut File) -> Result<(), io::Error> {
        file.write(&self.version.to_le_bytes())?;
        file.write(&self.name)?;
        file.write(&self.key_type.to_le_bytes())?;
        file.write(&self.public_key_size.to_le_bytes())?;
        file.write(&self.private_key_size.to_le_bytes())?;
        Ok(())
    }
}