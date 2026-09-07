//! One wire format for the timestamps the store writes.
//!
//! SQLite compares TEXT columns byte by byte, so `ORDER BY created_at` and
//! `expires_at <= now` are only correct when every value has the same shape.
//! Earlier releases wrote `DateTime::to_rfc3339()`, whose fractional part
//! varies with the value (`.5`, `.500`, `.500000000`, or nothing), so a row
//! with more digits could sort after a later row with fewer. Every write now
//! goes through [`format_timestamp`] and every read through
//! [`parse_timestamp`], which still accepts the older values.

use chrono::{DateTime, NaiveDateTime, SecondsFormat, Utc};

/// RFC 3339 in UTC with exactly six fractional digits and a `Z` suffix:
/// `2026-03-01T12:00:00.250000Z`. Sub-microsecond precision is dropped.
pub fn format_timestamp(dt: &DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// Parse a stored timestamp: what [`format_timestamp`] writes, what earlier
/// releases wrote (RFC 3339 with any fractional precision and any offset),
/// and SQLite's own `CURRENT_TIMESTAMP` form (`YYYY-MM-DD HH:MM:SS`, UTC).
pub fn parse_timestamp(s: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    match DateTime::parse_from_rfc3339(s) {
        Ok(dt) => Ok(dt.with_timezone(&Utc)),
        Err(rfc3339_err) => NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
            .map(|naive| naive.and_utc())
            .map_err(|_| rfc3339_err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn writes_fixed_microsecond_precision_with_z() {
        let base = Utc.with_ymd_and_hms(2026, 3, 1, 12, 0, 0).unwrap();
        assert_eq!(format_timestamp(&base), "2026-03-01T12:00:00.000000Z");
        assert_eq!(
            format_timestamp(&(base + chrono::Duration::milliseconds(250))),
            "2026-03-01T12:00:00.250000Z"
        );
        assert_eq!(
            format_timestamp(&(base + chrono::Duration::nanoseconds(123_456_789))),
            "2026-03-01T12:00:00.123456Z"
        );
    }

    #[test]
    fn round_trips_what_it_writes() {
        let now = Utc::now();
        let written = format_timestamp(&now);
        let read = parse_timestamp(&written).expect("parse");
        assert_eq!(format_timestamp(&read), written);
    }

    #[test]
    fn reads_older_free_precision_values_and_sqlite_defaults() {
        let base = Utc.with_ymd_and_hms(2026, 3, 1, 12, 0, 0).unwrap();
        assert_eq!(parse_timestamp("2026-03-01T12:00:00+00:00").unwrap(), base);
        assert_eq!(
            parse_timestamp("2026-03-01T12:00:00.750000000+00:00").unwrap(),
            base + chrono::Duration::milliseconds(750)
        );
        assert_eq!(parse_timestamp("2026-03-01T13:00:00+01:00").unwrap(), base);
        assert_eq!(parse_timestamp("2026-03-01T12:00:00Z").unwrap(), base);
        assert_eq!(parse_timestamp("2026-03-01 12:00:00").unwrap(), base);
        assert!(parse_timestamp("yesterday").is_err());
    }

    #[test]
    fn new_values_sort_correctly_against_old_ones_as_text() {
        let base = Utc.with_ymd_and_hms(2026, 3, 1, 12, 0, 0).unwrap();
        let new_250 = format_timestamp(&(base + chrono::Duration::milliseconds(250)));
        let old_zero = "2026-03-01T12:00:00+00:00";
        let old_750 = "2026-03-01T12:00:00.750+00:00";
        let old_next_second = "2026-03-01T12:00:01+00:00";
        let mut values = vec![old_750, &new_250, old_next_second, old_zero];
        values.sort();
        assert_eq!(values, vec![old_zero, &new_250, old_750, old_next_second]);
    }
}
