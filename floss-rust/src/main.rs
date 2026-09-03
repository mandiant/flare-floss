use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use serde_json;

mod layout;
mod strings;
mod tags;
mod results;

const FLOSS_DIR: &str = "/usr/local/google/home/moritzraabe/code/flare-floss";

fn print_usage_and_exit() {
    eprintln!("Usage: floss-rust <samples>...");
    std::process::exit(1);
}

fn load_databases() -> (tags::ExpertStringDatabase, tags::OpenSourceStringDatabase, tags::StringHashDatabase) {
    let base = PathBuf::from(FLOSS_DIR).join("floss").join("tags").join("data");
    
    let expert = tags::ExpertStringDatabase::from_uncompressed_file(base.join("expert").join("capa.jsonl")).unwrap();
    let oss = tags::OpenSourceStringDatabase::from_file(base.join("oss").join("openssl.jsonl.gz")).unwrap_or_else(|_| tags::OpenSourceStringDatabase { metadata_by_string: std::collections::HashMap::new() });
    
    let mut gp = tags::StringHashDatabase { string_hashes: std::collections::HashSet::new() };
    for file in &["gp-2026-hashes.bin", "xaa-hashes.bin", "yaa-hashes.bin", "gp-go-specific.bin", "gp-rust-specific.bin", "gp-pyinstaller-specific.bin"] {
        if let Ok(db) = tags::StringHashDatabase::from_file(base.join("gp").join(file)) {
            gp.string_hashes.extend(db.string_hashes);
        }
    }

    (expert, oss, gp)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage_and_exit();
    }

    let (expert_db, os_db, gp_db) = load_databases();

    for path_str in &args[1..] {
        let path = Path::new(path_str);
        if !path.exists() {
            eprintln!("File not found: {}", path_str);
            continue;
        }

        let buf = fs::read(path).unwrap();
        let layout_info = layout::compute_layout(&buf);
        let code_ranges = layout::get_code_ranges(&layout_info.data);
        let reloc_ranges = layout::get_reloc_ranges(&layout_info.data);

        let mut static_strings = Vec::new();
        static_strings.extend(strings::extract_ascii_strings(&buf, 4));
        static_strings.extend(strings::extract_unicode_strings(&buf, 4));
        static_strings.sort_by_key(|s| s.offset);

        let tagged = tags::tag_strings(
            &static_strings,
            &code_ranges,
            &reloc_ranges,
            &layout_info,
            Some(&expert_db),
            Some(&os_db),
            Some(&gp_db),
        );

        let doc = results::ResultDocument {
            metadata: results::Metadata {
                file_path: path_str.clone(),
                md5: String::new(),
                sha1: String::new(),
                sha256: String::new(),
                version: "3.2.0".to_string(), 
                imagebase: 0,
                min_length: 4,
                runtime: results::Runtime::default(),
                language: String::new(),
                language_version: String::new(),
                language_selected: String::new(),
            },
            analysis: results::Analysis::default(),
            strings: results::Strings {
                static_strings: tagged,
                ..Default::default()
            },
            layout: None,
        };

        match serde_json::to_string_pretty(&doc) {
            Ok(json) => println!("{}", json),
            Err(e) => eprintln!("Error serializing: {}", e),
        }
    }
}
