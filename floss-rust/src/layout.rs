// Layout parsing and obfuscation handling

use goblin::Object;

pub struct Layout {
    pub name: String,
    pub offset: usize,
    pub length: usize,
    pub data: Vec<u8>, // Decoded data if XORed, or original
    pub xor_key: Option<u8>,
    pub children: Vec<Layout>,
}

pub fn xor_static(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|&b| b ^ key).collect()
}

pub fn detect_xor_key(buf: &[u8]) -> Option<u8> {
    if buf.len() < 2 {
        return None;
    }

    let first = buf[0];
    let second = buf[1];

    let key = first ^ b'M';
    if (second ^ key) == b'Z' {
        if key == 0 {
            return None; // Not XORed
        }
        return Some(key);
    }

    None
}

pub fn compute_layout(buf: &[u8]) -> Layout {
    let mut xor_key = None;
    let mut data = buf.to_vec();
    let mut name = "binary".to_string();

    if let Some(key) = detect_xor_key(buf) {
        let decoded = xor_static(buf, key);
        if decoded.starts_with(b"MZ") {
            data = decoded;
            xor_key = Some(key);
            name = format!("pe (XOR decoded with key: 0x{:02x})", key);
        }
    }

    let mut children = Vec::new();

    if let Ok(obj) = Object::parse(&data) {
        match obj {
            Object::PE(pe) => {
                if xor_key.is_none() {
                    name = "pe".to_string();
                }
                for section in pe.sections {
                    if section.size_of_raw_data == 0 {
                        continue;
                    }
                    let s_name = section.name().unwrap_or("(invalid)").to_string();
                    let offset = section.pointer_to_raw_data as usize;
                    let size = section.size_of_raw_data as usize;

                    // TODO: Add bounds checking similar to Python

                    children.push(Layout {
                        name: s_name,
                        offset,
                        length: size,
                        data: Vec::new(), // Not needed for children
                        xor_key: None,
                        children: Vec::new(),
                    });
                }
                
                // TODO: Add header and overlay segments
            }
            Object::Elf(_elf) => {
                if xor_key.is_none() {
                    name = "elf".to_string();
                }
                // TODO: Handle ELF sections
            }
            _ => {}
        }
    }

    Layout {
        name,
        offset: 0,
        length: data.len(),
        data,
        xor_key,
        children,
    }
}

use std::ops::Range;

pub fn get_code_ranges(buf: &[u8]) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();

    // Lancelot only supports PE for now in this context?
    // Let's try to load as PE.
    if let Ok(pe) = lancelot::loader::pe::PE::from_bytes(buf) {
        let config = Box::new(lancelot::workspace::config::DynamicConfiguration::default());
        if let Ok(ws) = lancelot::workspace::PEWorkspace::from_pe(config, pe) {
            let base_address = ws.pe.module.address_space.base_address;
            
            // We need goblin PE to translate RVAs to file offsets
            if let Ok(goblin_pe) = ws.pe.pe() {
                let file_alignment = if let Some(opt_header) = &goblin_pe.header.optional_header {
                    opt_header.windows_fields.file_alignment
                } else {
                    512 // Default
                };

                let opts = goblin::pe::options::ParseOptions::default();

                for (_va, bb) in ws.cfg.basic_blocks.blocks_by_address.iter() {
                    let rva = bb.address - base_address;
                    if let Some(offset) = goblin::pe::utils::find_offset(rva as usize, &goblin_pe.sections, file_alignment, &opts) {
                        ranges.push(offset..(offset + bb.length as usize));
                    }
                }
            }
        }
    }

    // Merge overlapping ranges? FLOSS Python code does:
    // merged_code_ranges = merge_overlapping_ranges(code_ranges)
    // We should probably do that too for efficiency later.

    ranges
}
