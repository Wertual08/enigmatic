use clap::Parser;
use cli::Cli;
use clipboard::{ClipboardContext, ClipboardProvider};
use domain::{entries::EntryService, secrets, passwords::ensure_password};
use storage::registries::RegistryRepository;

use crate::{cli::CliCommand, domain::passwords::ensure_new_password};

mod cli;
mod domain;
mod storage;

fn main() {
    let cli = Cli::parse();

    let storage = if let Some(path) = cli.storage {
        path
    } 
    else {
        home::home_dir().unwrap().join(".enigmatic")
    };

    match cli.command {
        CliCommand::Init { name, password } => {
            let name = if let Some(name) = name {
                name
            }
            else {
                whoami::username()
            };

            let password = ensure_new_password(password);
            
            RegistryRepository::init(&storage, &name, &password).unwrap();
        },
        CliCommand::Ls {  } => {
            let registry_repository = RegistryRepository::open(&storage).unwrap();
            let entry_service = EntryService::new(registry_repository).unwrap();
            
            println!("Registry [{}] content:", entry_service.registry_name());
            for (name, entry) in entry_service.entries {
                println!("{:32}: {}", name, entry.description)
            }
        },
        CliCommand::Copy { name, password } => {
            let password = ensure_password(password);

            let registry_repository = RegistryRepository::open_decrypt(&storage, &password).unwrap();
            let entry_service = EntryService::new(registry_repository).unwrap();

            let entry = entry_service.entries.get(&name);

            if let Some(entry) = entry {
                let secret = entry_service.decrypt_secret(&entry.secret);
                if let Some(secret) = secret {
                    let decoded = std::str::from_utf8(&secret).unwrap();
                    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
                    ctx.set_contents(String::from(decoded)).unwrap();
                }
                else {
                    println!("Unable to decrypt secret");
                }
            }
            else {
                println!("Missing entry for given name");
            }
        },
        CliCommand::Show { name, password, copy } => {
            let password = ensure_password(password);

            let registry_repository = RegistryRepository::open_decrypt(&storage, &password).unwrap();
            let entry_service = EntryService::new(registry_repository).unwrap();

            let entry = entry_service.entries.get(&name);

            if let Some(entry) = entry {
                let secret = entry_service.decrypt_secret(&entry.secret);
                if let Some(secret) = secret {
                    let decoded = std::str::from_utf8(&secret).unwrap();
                    if copy {
                        let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
                        ctx.set_contents(String::from(decoded)).unwrap();
                    }

                    println!("{}: {}", name, entry.description);
                    println!("{}", decoded);
                }
                else {
                    println!("Unable to decrypt secret");
                }
            }
            else {
                println!("Missing entry for given name");
            }
        },
        CliCommand::Add { name, description, secret, generate, copy } => {
            let secret = if let Some(secret) = secret {
                secret
            }
            else {
                secrets::generate(&generate.unwrap())
            };

            if copy {
                let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
                ctx.set_contents(secret.clone()).unwrap();
            }

            let secret_bytes = secret.into_bytes();

            let registry_repository = RegistryRepository::open(&storage).unwrap();
            let mut entry_service = EntryService::new(registry_repository).unwrap();
            entry_service.add(name, description.unwrap_or(String::new()), secret_bytes).unwrap();
        },
        CliCommand::Set { name, new_name, description, secret, generate, copy } => {
            let secret = if let Some(secret) = secret {
                Some(secret)
            }
            else if let Some(generate) = generate {
                Some(secrets::generate(&generate))
            }
            else {
                None
            };

            if let Some(secret) = &secret {
                if copy {
                    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
                    ctx.set_contents(secret.clone()).unwrap();
                }
            }

            let secret_bytes = secret.map(|x| x.into_bytes());

            let registry_repository = RegistryRepository::open(&storage).unwrap();
            let mut entry_service = EntryService::new(registry_repository).unwrap();
            entry_service.set(name, new_name, description, secret_bytes).unwrap();
        },
        CliCommand::Del { name } => {
            let registry_repository = RegistryRepository::open(&storage).unwrap();
            let mut entry_service = EntryService::new(registry_repository).unwrap();
            entry_service.del(name).unwrap();
        },
    }
}