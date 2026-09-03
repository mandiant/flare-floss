// Layout parsing and obfuscation handling

pub fn xor_static(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|&b| b ^ key).collect()
}

pub fn detect_xor_key(buf: &[u8]) -> Option<u8> {
    if buf.len() < 2 {
        return None;
    }

    let first = buf[0];
    let second = buf[1];

    // Try to find a key such that (first ^ key == 'M') and (second ^ key == 'Z')
    // 'M' is 0x4D, 'Z' is 0x5A
    
    let key = first ^ b'M';
    if (second ^ key) == b'Z' {
        if key == 0 {
            return None; // Not XORed
        }
        return Some(key);
    }

    None
}

pub struct Layout {
    pub name: String,
    pub data: Vec<u8>, // Decoded data if XORed, or original
    pub xor_key: Option<u8>,
}

pub fn compute_layout(buf: &[u8]) -> Layout {
    if let Some(key) = detect_xor_key(buf) {
        let decoded = xor_static(buf, key);
        if decoded.starts_with(b"MZ") {
            return Layout {
                name: format!("pe (XOR decoded with key: 0x{:02x})", key),
                data: decoded,
                xor_key: Some(key),
            };
        }
        // TODO: Handle ELF with XOR? Python plan says "透明 XOR 解码 for PE files" (Transparent XOR decoding for PE files).
        // Let's re-read the plan.
        // Step 2.1: "Implement transparent XOR detection (checking for XORed MZ headers) matching floss.layout.compute_layout".
        // Step 1.3 in Scope: "Format Handling: PE and ELF format understanding, including transparent XOR decoding for PE files."
        // So maybe only for PE?
        // Let's check Python code again.
    }

    if buf.starts_with(b"MZ") {
        return Layout {
            name: "pe".to_string(),
            data: buf.to_vec(),
            xor_key: None,
        };
    } else if buf.starts_with(b"\x7fELF") {
         return Layout {
            name: "elf".to_string(),
            data: buf.to_vec(),
            xor_key: None,
        };
    }

    Layout {
        name: "binary".to_string(),
            data: buf.to_vec(),
            xor_key: None,
    }
}
