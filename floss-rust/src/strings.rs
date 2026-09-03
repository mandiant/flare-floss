use std::borrow::Cow;

pub struct StaticString<'a> {
    pub string: Cow<'a, str>,
    pub offset: usize,
    pub encoding: StringEncoding,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StringEncoding {
    ASCII,
    UTF16LE,
}

pub const MIN_LENGTH: usize = 4;

// Heuristic repeat characters
pub const REPEATS: [u8; 4] = [b'A', 0x00, 0xFE, 0xFF];

pub fn is_ascii_printable(c: u8) -> bool {
    (0x20..=0x7E).contains(&c) || c == b'\t'
}

pub fn buf_filled_with(buf: &[u8], character: u8) -> bool {
    if buf.is_empty() {
        return false;
    }
    buf.iter().all(|&b| b == character)
}

pub fn extract_ascii_strings<'a>(buf: &'a [u8], min_length: usize) -> Vec<StaticString<'a>> {
    let mut strings = Vec::new();
    if buf.is_empty() {
        return strings;
    }

    if REPEATS.contains(&buf[0]) && buf_filled_with(buf, buf[0]) {
        return strings;
    }

    let mut start = 0;
    let mut in_string = false;

    for (i, &b) in buf.iter().enumerate() {
        if is_ascii_printable(b) {
            if !in_string {
                start = i;
                in_string = true;
            }
        } else {
            if in_string {
                let length = i - start;
                if length >= min_length {
                    // Safety: We only included printable ASCII characters which are valid UTF-8
                    let s = unsafe { std::str::from_utf8_unchecked(&buf[start..i]) };
                    strings.push(StaticString {
                        string: Cow::Borrowed(s),
                        offset: start,
                        encoding: StringEncoding::ASCII,
                    });
                }
                in_string = false;
            }
        }
    }

    // Handle string at the end of buffer
    if in_string {
        let length = buf.len() - start;
        if length >= min_length {
            let s = unsafe { std::str::from_utf8_unchecked(&buf[start..]) };
            strings.push(StaticString {
                string: Cow::Borrowed(s),
                offset: start,
                encoding: StringEncoding::ASCII,
            });
        }
    }

    strings
}

pub fn extract_unicode_strings<'a>(buf: &'a [u8], min_length: usize) -> Vec<StaticString<'a>> {
    let mut strings = Vec::new();
    if buf.is_empty() {
        return strings;
    }

    if REPEATS.contains(&buf[0]) && buf_filled_with(buf, buf[0]) {
        return strings;
    }

    let mut i = 0;
    while i < buf.len().saturating_sub(1) {
        if is_ascii_printable(buf[i]) && buf[i + 1] == 0 {
            let start = i;
            let mut j = i;
            while j < buf.len().saturating_sub(1) && is_ascii_printable(buf[j]) && buf[j + 1] == 0 {
                j += 2;
            }
            let length = (j - start) / 2;
            if length >= min_length {
                // Decode UTF-16LE
                let u16_chars: Vec<u16> = (start..j)
                    .step_by(2)
                    .map(|k| u16::from_le_bytes([buf[k], buf[k + 1]]))
                    .collect();
                
                if let Ok(s) = String::from_utf16(&u16_chars) {
                    strings.push(StaticString {
                        string: Cow::Owned(s),
                        offset: start,
                        encoding: StringEncoding::UTF16LE,
                    });
                }
            }
            i = j; // Advance past the string
        } else {
            i += 1;
        }
    }

    strings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ascii() {
        let buf = b"Hello World!\x00Some garbage\x01Another string";
        let strings = extract_ascii_strings(buf, 4);
        assert_eq!(strings.len(), 3);
        assert_eq!(strings[0].string, "Hello World!");
        assert_eq!(strings[0].offset, 0);
        assert_eq!(strings[1].string, "Some garbage");
        assert_eq!(strings[1].offset, 13);
        assert_eq!(strings[2].string, "Another string");
        assert_eq!(strings[2].offset, 26);
    }

    #[test]
    fn test_extract_unicode() {
        // "Hello" in UTF-16LE
        let buf = [
            b'H', 0, b'e', 0, b'l', 0, b'l', 0, b'o', 0, 1, 2, // garbage
            b'W', 0, b'o', 0, b'r', 0, b'l', 0, b'd', 0,
        ];
        let strings = extract_unicode_strings(&buf, 4);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].string, "Hello");
        assert_eq!(strings[0].offset, 0);
        assert_eq!(strings[1].string, "World");
        assert_eq!(strings[1].offset, 12);
    }

    #[test]
    fn test_repeats() {
        let buf = [b'A'; 100];
        let strings = extract_ascii_strings(&buf, 4);
        assert!(strings.is_empty());

        let buf = [0u8; 100];
        let strings = extract_ascii_strings(&buf, 4);
        assert!(strings.is_empty());
    }
}
