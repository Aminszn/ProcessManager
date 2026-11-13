/// Formats memory bytes as a hexadecimal and ASCII dump.
pub fn format_hex_ascii(
    start_address: u64,
    bytes: &[u8],
    bytes_per_line: usize,
) -> Result<String, String> {
    if bytes_per_line == 0 {
        return Err("Bytes per line must be greater than zero".to_string());
    }

    let mut output = String::new();

    for (line_index, chunk) in bytes.chunks(bytes_per_line).enumerate() {
        let offset = line_index * bytes_per_line;

        let address = start_address
            .checked_add(offset as u64)
            .ok_or_else(|| "Memory address overflow".to_string())?;

        // Virtual memory address.
        output.push_str(&format!("{address:016X}  "));

        // Hexadecimal representation.
        for byte in chunk {
            output.push_str(&format!("{byte:02X} "));
        }

        // Align ASCII column for incomplete lines.
        for _ in chunk.len()..bytes_per_line {
            output.push_str("   ");
        }

        output.push_str(" |");

        // Printable ASCII representation.
        for byte in chunk {
            let character = if (0x20..=0x7E).contains(byte) {
                *byte as char
            } else {
                '.'
            };

            output.push(character);
        }

        output.push('\n');
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_hex_and_ascii() {
        let bytes = b"ABC\x00";

        let result = format_hex_ascii(0x1000, bytes, 4).unwrap();

        assert_eq!(result, "0000000000001000  41 42 43 00  |ABC.\n");
    }

    #[test]
    fn formats_multiple_lines() {
        let bytes = b"ABCDEFGH";

        let result = format_hex_ascii(0x1000, bytes, 4).unwrap();

        assert_eq!(
            result,
            "0000000000001000  41 42 43 44  |ABCD\n\
             0000000000001004  45 46 47 48  |EFGH\n"
        );
    }

    #[test]
    fn rejects_zero_bytes_per_line() {
        let result = format_hex_ascii(0x1000, b"ABC", 0);

        assert!(result.is_err());
    }

    #[test]
    fn handles_empty_memory() {
        let result = format_hex_ascii(0x1000, b"", 16).unwrap();

        assert!(result.is_empty());
    }
}

#[test]
fn rejects_address_overflow_across_lines() {
    let bytes = b"ABCD";

    let result = format_hex_ascii(u64::MAX - 1, bytes, 2);

    assert!(
        result.is_err(),
        "Formatting should reject an address overflow"
    );

    assert_eq!(result.unwrap_err(), "Memory address overflow");
}
