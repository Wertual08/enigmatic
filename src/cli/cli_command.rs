use clap::{Subcommand, arg};

#[derive(Subcommand)]
pub enum CliCommand {
    /// Initialize secret registry
    Init {
        /// Registry name
        name: Option<String>,
        
        // Registry password
        #[arg(short, long)]
        password: Option<String>,
    },

    /// List entries
    Ls {
    },

    /// Copy entry secret to clipboard
    Copy {
        /// Entry name
        name: String,
        
        /// Registry password
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Display entry with secret
    Show {
        /// Entry name
        name: String,
        
        /// Registry password
        #[arg(short, long)]
        password: Option<String>,

        /// Copy secret to clipboard
        #[arg(short, long)]
        copy: bool,
    },

    /// Add entry
    Add {
        /// Entry name
        name: String,
        
        /// Entry description
        #[arg(short, long)]
        description: Option<String>,

        /// Entry secret
        #[arg(short, long, required_unless_present("generate"))]
        secret: Option<String>,

        /// Generate entry secret {length:[d][s][l][u]}
        /// d - use digits
        /// s - use symbols
        /// l - use lowercase letters
        /// u - use uppercase letters
        #[arg(short, long, required_unless_present("secret"))]
        generate: Option<String>,

        /// Copy secret to clipboard
        #[arg(short, long)]
        copy: bool,
    },
    

    /// Set entry
    Set {
        /// Entry name
        name: String,

        //// New entry name
        #[arg(short, long)]
        new_name: Option<String>,
        
        /// Entry description
        #[arg(short, long)]
        description: Option<String>,

        /// Entry secret
        #[arg(short, long)]
        secret: Option<String>,

        /// Generate entry secret {length:[n][s][l][L]}
        /// n - use numbers
        /// s - use symbols
        /// l - use lowercase letters
        /// L - use uppercase letters
        #[arg(short, long)]
        generate: Option<String>,

        /// Copy secret to clipboard
        #[arg(short, long, requires("secret"), requires("generate"))]
        copy: bool,
    },
    

    /// Delete entry
    Del {
        /// Entry name
        name: String,
    }    
}