
extern crate sha;

use sha::*;
use std::io::prelude::*;
use std::fs;
use std::env;

pub fn to_hex_string(bytes: &[u8]) -> String {
  let strs: Vec<String> = bytes.iter()
                               .map(|b| format!("{:02x}", b))
                               .collect();
  strs.join("")
}

fn main() {
    let mut sha256: Sha256 = Sha256::new();
    let mut sha512: Sha512 = Sha512::new();
    let mut input: [u8; 64] = [0; 64];
    let output256: &[u8; 32];
    let output512: &[u8; 64];
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: {} filename", args[0]);
        return ;
    }

    let mut f: fs::File = fs::File::open(&args[1]).unwrap();

    loop {
        let size: usize = f.read(&mut input).unwrap();
        if size == 0 {
            break;
        }

        sha256.update(&input[0..size]);
        sha512.update(&input[0..size]);
    }

    output256 = sha256.finish();
    output512 = sha512.finish();

    println!("sha256: {}", to_hex_string(output256));
    println!("sha512: {}", to_hex_string(output512));
}

