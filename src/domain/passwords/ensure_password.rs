use std::{env, io::{self, Write}};

use rpassword::read_password;

pub fn ensure_password(password: Option<String>) -> String {
    if let Some(password) = password {
        return password;
    }

    if let Ok(password) = env::var("ENIGMATIC_PASSWORD") {
        return password;
    }

    print!("Password: ");
    io::stdout().flush().unwrap();
    read_password().unwrap()
}

pub fn ensure_new_password(password: Option<String>) -> String {
    if let Some(password) = password {
        return password;
    }
    
    if let Ok(password) = env::var("ENIGMATIC_PASSWORD") {
        return password;
    }

    loop {
        print!("Password: ");
        io::stdout().flush().unwrap();
        let password = read_password().unwrap();

        print!("Repeat: ");
        io::stdout().flush().unwrap();
        if password == read_password().unwrap() {
            return password;
        }

        println!("Passwords are not equal");
    }
}