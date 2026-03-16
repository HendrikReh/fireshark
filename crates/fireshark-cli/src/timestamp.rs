use std::time::Duration;

/// Format a Duration (since Unix epoch) as ISO 8601 UTC with millisecond precision.
pub fn format_utc(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    let millis = duration.subsec_millis();

    let day_secs = total_secs % 86_400;
    let hour = day_secs / 3_600;
    let minute = (day_secs % 3_600) / 60;
    let second = day_secs % 60;

    let (year, month, day) = civil_from_days((total_secs / 86_400) as i64);

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Howard Hinnant's civil_from_days algorithm.
/// Converts days since Unix epoch (1970-01-01) to (year, month, day).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_epoch() {
        // 2023-11-14T22:13:20.000Z
        let ts = Duration::from_secs(1_700_000_000);
        assert_eq!(format_utc(ts), "2023-11-14T22:13:20.000Z");
    }

    #[test]
    fn formats_with_milliseconds() {
        let ts = Duration::from_millis(1_700_000_000_123);
        assert_eq!(format_utc(ts), "2023-11-14T22:13:20.123Z");
    }

    #[test]
    fn formats_leap_year() {
        // 2024-02-29T00:00:00.000Z
        let ts = Duration::from_secs(1_709_164_800);
        assert_eq!(format_utc(ts), "2024-02-29T00:00:00.000Z");
    }

    #[test]
    fn formats_unix_epoch_zero() {
        assert_eq!(format_utc(Duration::ZERO), "1970-01-01T00:00:00.000Z");
    }
}
