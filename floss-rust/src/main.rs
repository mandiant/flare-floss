use std::env;
use std::fs;
use std::path::Path;

mod layout;
mod strings;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <file_path>", args[0]);
        std::process::exit(1);
    }

    let file_path = &args[1];
    let path = Path::new(file_path);

    if !path.exists() {
        eprintln!("Error: File not found: {}", file_path);
        std::process::exit(1);
    }

    let buf = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading file: {}", e);
            std::process::exit(1);
        }
    };

    println!("Analyzing: {}", file_path);

    let layout = layout::compute_layout(&buf);
    println!("Layout type: {}", layout.name);

    if let Some(key) = layout.xor_key {
        println!("XOR key detected: 0x{:02x}", key);
    }

    // For now, just extract strings from the whole buffer (or decoded buffer)
    let ascii_strings = strings::extract_ascii_strings(&layout.data, strings::MIN_LENGTH);
    let unicode_strings = strings::extract_unicode_strings(&layout.data, strings::MIN_LENGTH);

    println!("Extracted {} ASCII strings", ascii_strings.len());
    println!("Extracted {} UTF-16LE strings", unicode_strings.len());

    // Print first few for verification
    println!("\nFirst 5 ASCII strings:");
    for s in ascii_strings.iter().take(5) {
        println!("0x{:x}: {}", s.offset, s.string);
    }

    println!("\nFirst 5 UTF-16LE strings:");
    for s in unicode_strings.iter().take(5) {
        println!("0x{:x}: {}", s.offset, s.string);
    }
}
