import re
from typing import Iterator, Tuple

'''This regular expression is strictly designed to match printable ASCII 
and valid UTF-8 multi-byte sequences.''' 

UTF8_PRINTABLE_PATTERN = re.compile(
    b'(?:'
    b'[\x20-\x7E\t\r\n]'                  # 1-byte: ASCII printable characters and standard whitespace
    b'|[\xC2-\xDF][\x80-\xBF]'            # 2-byte: Valid UTF-8 sequence
    b'|\xE0[\xA0-\xBF][\x80-\xBF]'        # 3-byte: Valid UTF-8 sequence
    b'|[\xE1-\xEC][\x80-\xBF]{2}'         # 3-byte: Valid UTF-8 sequence
    b'|\xED[\x80-\x9F][\x80-\xBF]'        # 3-byte: Valid UTF-8 sequence
    b'|[\xEE-\xEF][\x80-\xBF]{2}'         # 3-byte: Valid UTF-8 sequence
    b'|\xF0[\x90-\xBF][\x80-\xBF]{2}'     # 4-byte: Valid UTF-8 sequence
    b'|[\xF1-\xF3][\x80-\xBF]{3}'         # 4-byte: Valid UTF-8 sequence
    b'|\xF4[\x80-\x8F][\x80-\xBF]{2}'     # 4-byte: Valid UTF-8 sequence
    b')+'
)

def extract_utf8_strings(buf: bytes, min_length: int = 4) -> Iterator[Tuple[int, str]]:
    """
    Scans a byte buffer and yields strictly valid, printable UTF-8 strings.
    Ignores UTF-16/wide strings completely to prevent garbage extraction in Rust binaries.
    
    Args:
        buf (bytes): The raw binary data to scan.
        min_length (int): The minimum character length for a valid string. Default is 4.
        
    Yields:
        Tuple[int, str]: A tuple containing the starting byte offset and the decoded string.
    """
    for match in UTF8_PRINTABLE_PATTERN.finditer(buf):
        string_bytes = match.group(0)
        
        try:
            # Decode the matched bytes into a standard Python string
            decoded_string = string_bytes.decode('utf-8')
            
            # Check if the length meets the minimum threshold
            if len(decoded_string) >= min_length:
                yield (match.start(), decoded_string)
                
        except UnicodeDecodeError:
            # Safely continue if an edge-case sequence bypasses the regex 
            # but fails the strict Python decoder.
            continue

if __name__ == "__main__":
    # Quick sanity check / localized test
    test_buffer = (
        b"Garbage\x00\x00\x00"              # Should be ignored or split
        b"Valid_UTF8_String\x00"            # Should extract "Valid_UTF8_String"
        b"W\x00i\x00d\x00e\x00"             # UTF-16 wide string: Should be completely ignored
        b"\xE2\x9C\x93_Checkmark\x00"       # Should extract "✓_Checkmark"
    )
    
    print("Extracting strings from test buffer...")
    for offset, extracted_str in extract_utf8_strings(test_buffer, min_length=4):
        print(f"Offset: {hex(offset)} | String: '{extracted_str}'")