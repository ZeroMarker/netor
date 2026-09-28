//! Human readable formatting for the tables printed by each subcommand.

use crate::cli::Unit;

pub fn format_rate(bytes_per_second: f64, unit: Unit) -> String {
    match unit {
        Unit::Auto | Unit::Bytes => format!("{}/s", format_bytes(bytes_per_second)),
        Unit::Bits => format!("{}/s", format_bits(bytes_per_second * 8.0)),
    }
}

pub fn format_bytes(bytes: f64) -> String {
    format_scaled(bytes, &["B", "KiB", "MiB", "GiB", "TiB"])
}

pub fn format_bits(bits: f64) -> String {
    format_scaled(bits, &["b", "Kib", "Mib", "Gib", "Tib"])
}

fn format_scaled(mut value: f64, units: &[&str]) -> String {
    let mut index = 0;
    while value >= 1024.0 && index < units.len() - 1 {
        value /= 1024.0;
        index += 1;
    }

    if index == 0 {
        format!("{value:.0} {}", units[index])
    } else if value < 10.0 {
        format!("{value:.2} {}", units[index])
    } else {
        format!("{value:.1} {}", units[index])
    }
}

pub fn trim_float(value: f64) -> String {
    let formatted = format!("{value:.3}");
    formatted
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_owned()
}

pub fn truncate(value: &str, width: usize) -> String {
    let mut chars = value.chars();
    let truncated = chars.by_ref().take(width).collect::<String>();

    if chars.next().is_some() && width >= 4 {
        format!(
            "{}...",
            truncated
                .chars()
                .take(width.saturating_sub(3))
                .collect::<String>()
        )
    } else {
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_bytes_with_binary_units() {
        assert_eq!(format_bytes(0.0), "0 B");
        assert_eq!(format_bytes(1023.0), "1023 B");
        assert_eq!(format_bytes(1024.0), "1.00 KiB");
        assert_eq!(format_bytes(10.0 * 1024.0), "10.0 KiB");
    }

    #[test]
    fn formats_large_byte_values() {
        assert_eq!(format_bytes(1024.0 * 1024.0), "1.00 MiB");
        assert_eq!(format_bytes(1024.0 * 1024.0 * 1024.0), "1.00 GiB");
        assert_eq!(format_bytes(1024.0 * 1024.0 * 1024.0 * 1024.0), "1.00 TiB");
    }

    #[test]
    fn formats_bits_with_binary_units() {
        assert_eq!(format_bits(0.0), "0 b");
        assert_eq!(format_bits(1024.0), "1.00 Kib");
        assert_eq!(format_bits(1024.0 * 1024.0), "1.00 Mib");
    }

    #[test]
    fn formats_rate_in_bytes_and_bits() {
        assert_eq!(format_rate(1024.0, Unit::Bytes), "1.00 KiB/s");
        assert_eq!(format_rate(1024.0, Unit::Bits), "8.00 Kib/s");
        assert_eq!(format_rate(1024.0, Unit::Auto), "1.00 KiB/s");
    }

    #[test]
    fn trims_trailing_zeros_from_float() {
        assert_eq!(trim_float(1.0), "1");
        assert_eq!(trim_float(1.500), "1.5");
        assert_eq!(trim_float(0.123), "0.123");
        assert_eq!(trim_float(2.001), "2.001");
    }

    #[test]
    fn truncates_long_interface_names() {
        assert_eq!(truncate("abcdefghijklmnopqrs", 18), "abcdefghijklmno...");
        assert_eq!(truncate("short", 18), "short");
        assert_eq!(truncate("exact18chars------", 18), "exact18chars------");
        assert_eq!(truncate("", 10), "");
        assert_eq!(truncate("abc", 1), "a");
        assert_eq!(truncate("abcdef", 3), "abc");
    }
}
