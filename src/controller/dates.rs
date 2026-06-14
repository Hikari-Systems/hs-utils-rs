//! Date helpers for the controller toolkit. ISO 8601 only — subscription dates
//! are emitted in ISO across all controllers (no locale formatting).

use chrono::{DateTime, NaiveDateTime, SecondsFormat, Utc};

/// Format a UTC datetime as ISO 8601 with millisecond precision and a numeric
/// offset (e.g. `2026-06-07T12:34:56.000+00:00`).
pub fn iso_utc(dt: &DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Millis, false)
}

/// Current time as a UTC ISO string.
pub fn now_iso() -> String {
    iso_utc(&Utc::now())
}

/// Parse an ISO 8601 string into a UTC datetime, returning `None` when invalid.
/// Accepts offset-bearing forms (`…+00:00`, `…Z`) and naive forms with no offset
/// (treated as UTC — how the data-services serialize `TIMESTAMP WITHOUT TIME
/// ZONE`).
pub fn parse_dt(v: Option<&str>) -> Option<DateTime<Utc>> {
    let s = v?.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
    ] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(ndt.and_utc());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn iso_uses_millis_and_offset() {
        let dt = Utc.with_ymd_and_hms(2026, 6, 7, 12, 34, 56).unwrap();
        assert_eq!(iso_utc(&dt), "2026-06-07T12:34:56.000+00:00");
    }

    #[test]
    fn parse_round_trips_and_naive() {
        let s = "2026-06-07T12:34:56.789+00:00";
        assert_eq!(iso_utc(&parse_dt(Some(s)).unwrap()), s);
        assert!(parse_dt(Some("2026-06-14 19:32:32")).is_some());
        assert!(parse_dt(Some("not-a-date")).is_none());
        assert!(parse_dt(None).is_none());
    }
}
