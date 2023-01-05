pub enum EntryOperationDto {
    Add {
        hash: [u8; 32],
        name: String,
        description: String,
        secret: Vec<u8>,
    },

    Set {
        hash: [u8; 32],
        src_name: String,
        dst_name: Option<String>,
        dst_description: Option<String>,
        dst_secret: Option<Vec<u8>>,
    },

    Del {
        hash: [u8; 32],
        name: String,
    },
}