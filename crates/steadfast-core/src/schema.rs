//! Deklarative Schema-Validierung fuer Mutationen (POST/PUT/PATCH).
//!
//! Die `[schema]`-Sektion eines Endpunkts wird beim Start in diese native
//! Struktur uebersetzt ([`EndpointSchema`]) — zur Laufzeit gibt es kein
//! Parsing und keine externe Schema-Bibliothek, nur Hash-Lookups und
//! Typ-Dispatch. Damit bleibt der Write-Hot-Path unangetastet: `validate`
//! alloziert im Fehlerfall nichts und kehrt ohne Fund sofort zurueck.
//!
//! Semantik:
//! * `required` — Felder, die im Dokument vorhanden sein MUESSEN (nur
//!   POST/PUT; bei PATCH wird der Check uebersprungen, weil ein Patch
//!   partiell ist).
//! * `types` — WENN ein Feld uebergeben wird, MUSS es den deklarierten Typ
//!   haben. Optional deklarierbar, auch fuer nicht-required Felder.
//! * `allow_unknown_fields` — false (Default) weist Felder ab, die weder in
//!   `required` noch in `types` deklariert sind.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

/// Die von der `apps.toml` akzeptierten Typen (`schema.types.feld = "..."`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldType {
    String,
    Number,
    Boolean,
    Object,
    Array,
    Null,
    /// ISO 8601 Kalenderdatum `YYYY-MM-DD` (z. B. `"2026-10-23"`).
    Date,
    /// RFC 3339 Zeitstempel, z. B. `"2026-10-23T14:30:00Z"` oder
    /// `"2026-10-23T14:30:00.250+02:00"` — Offset ist Pflicht.
    DateTime,
}

impl FieldType {
    /// Parst den TOML-Typ-String; `None` = unbekannter Typ (Fail-Fast beim
    /// Start, der Aufrufer formatiert den Config-Fehler).
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "string" => Some(FieldType::String),
            "number" => Some(FieldType::Number),
            "boolean" => Some(FieldType::Boolean),
            "object" => Some(FieldType::Object),
            "array" => Some(FieldType::Array),
            "null" => Some(FieldType::Null),
            "date" => Some(FieldType::Date),
            "datetime" => Some(FieldType::DateTime),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            FieldType::String => "string",
            FieldType::Number => "number",
            FieldType::Boolean => "boolean",
            FieldType::Object => "object",
            FieldType::Array => "array",
            FieldType::Null => "null",
            FieldType::Date => "date",
            FieldType::DateTime => "datetime",
        }
    }

    /// Prueft einen JSON-Wert gegen den deklarierten Typ. JSON hat genau
    /// einen Zahltyp — Ganzzahl und Gleitkomma sind beides `number`. Die
    /// Datumstypen pruefen das String-Format byte-weise (ohne Datums-
    /// Bibliothek, s. `is_valid_date`/`is_valid_datetime`).
    fn matches(self, value: &Value) -> bool {
        match self {
            FieldType::String => value.is_string(),
            FieldType::Number => value.is_number(),
            FieldType::Boolean => value.is_boolean(),
            FieldType::Object => value.is_object(),
            FieldType::Array => value.is_array(),
            FieldType::Null => value.is_null(),
            FieldType::Date => value.as_str().is_some_and(is_valid_date),
            FieldType::DateTime => value.as_str().is_some_and(is_valid_datetime),
        }
    }
}

/// Strenges ISO 8601 Kalenderdatum: `YYYY-MM-DD` mit vierstelligem Jahr,
/// Monat 01-12 und monatsabhaengigem Tag inkl. Schaltjahren (durch 4,
/// ausser durch 100, ausser durch 400). Nicht gepolsterte Formen
/// (`2024-1-1`) sind ungueltig.
fn is_valid_date(s: &str) -> bool {
    is_valid_date_bytes(s.as_bytes())
}

fn is_valid_date_bytes(b: &[u8]) -> bool {
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let (year, ok) = digits4(&b[0..4]);
    if !ok {
        return false;
    }
    let (month, ok) = digits2(&b[5..7]);
    if !ok || !(1..=12).contains(&month) {
        return false;
    }
    let (day, ok) = digits2(&b[8..10]);
    ok && day >= 1 && day <= days_in_month(year, month)
}

/// RFC 3339 Zeitstempel: Datum + `T`/`t` + `HH:MM:SS` (Sekunde 60 =
/// Schaltsekunde erlaubt) + optionale Sekundenbruchteile + PFLICHT-Zone
/// (`Z`/`z` oder `±HH:MM`) — ohne Zone ist der Zeitpunkt mehrdeutig.
fn is_valid_datetime(s: &str) -> bool {
    let b = s.as_bytes();
    // Kuerzeste gueltige Form: "YYYY-MM-DDTHH:MM:SSZ" = 20 Bytes.
    if b.len() < 20 || (b[10] != b'T' && b[10] != b't') || !is_valid_date_bytes(&b[0..10]) {
        return false;
    }
    let (hour, ok) = digits2(&b[11..13]);
    if !ok || hour > 23 {
        return false;
    }
    if b[13] != b':' {
        return false;
    }
    let (minute, ok) = digits2(&b[14..16]);
    if !ok || minute > 59 {
        return false;
    }
    if b[16] != b':' {
        return false;
    }
    let (second, ok) = digits2(&b[17..19]);
    if !ok || second > 60 {
        return false;
    }

    // Optionale Sekundenbruchteile (mindestens eine Ziffer nach dem Punkt).
    let mut i = 19;
    if b[i] == b'.' {
        i += 1;
        let frac_start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == frac_start {
            return false;
        }
    }

    // Zone ist Pflicht: `Z`/`z` oder `±HH:MM` mit gueltiger Uhrzeit.
    match b.len() - i {
        1 => b[i] == b'Z' || b[i] == b'z',
        6 => {
            let (off_hour, ok) = digits2(&b[i + 1..i + 3]);
            let (off_min, okm) = digits2(&b[i + 4..i + 6]);
            (b[i] == b'+' || b[i] == b'-')
                && b[i + 3] == b':'
                && ok
                && off_hour <= 23
                && okm
                && off_min <= 59
        }
        _ => false,
    }
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                29
            } else {
                28
            }
        }
        // Der Aufrufer prueft 1..=12 vorher; ungueltige Monate scheitern
        // schon am Bereichscheck, nicht an dieser Tabelle.
        _ => unreachable!("month validated by caller"),
    }
}

/// Zwei ASCII-Ziffern als `u32`; `(0, false)` bei allem anderen.
fn digits2(b: &[u8]) -> (u32, bool) {
    if b.len() == 2 && b[0].is_ascii_digit() && b[1].is_ascii_digit() {
        ((u32::from(b[0] - b'0') * 10) + u32::from(b[1] - b'0'), true)
    } else {
        (0, false)
    }
}

fn digits4(b: &[u8]) -> (u32, bool) {
    if b.len() == 4 && b.iter().all(u8::is_ascii_digit) {
        (
            u32::from(b[0] - b'0') * 1000
                + u32::from(b[1] - b'0') * 100
                + u32::from(b[2] - b'0') * 10
                + u32::from(b[3] - b'0'),
            true,
        )
    } else {
        (0, false)
    }
}

/// Vorkompiliertes Endpoint-Schema: beim Start gebaut, danach read-only
/// (`Arc`-geteilt zwischen allen Request-Workern).
#[derive(Debug, Clone, Default)]
pub struct EndpointSchema {
    required: HashSet<String>,
    types: HashMap<String, FieldType>,
    allow_unknown: bool,
}

impl EndpointSchema {
    /// Baut das Schema aus den bereits validierten TOML-Werten (Feldnamen
    /// und Typ-Strings prueft der Config-Loader mit Fail-Fast, bevor hier
    /// etwas landet). Doppelte `required`-Eintraege werden dedupliziert.
    pub fn new(
        required: Vec<String>,
        types: HashMap<String, FieldType>,
        allow_unknown: bool,
    ) -> Self {
        EndpointSchema {
            required: required.into_iter().collect(),
            types,
            allow_unknown,
        }
    }

    pub fn required(&self) -> &HashSet<String> {
        &self.required
    }

    pub fn types(&self) -> &HashMap<String, FieldType> {
        &self.types
    }

    pub fn allow_unknown_fields(&self) -> bool {
        self.allow_unknown
    }

    /// Validiert ein JSON-Dokument gegen das Schema und sammelt ALLE
    /// Verletzungen (nicht nur die erste). `partial = true` (PATCH) haelt
    /// sich an die Teilmengen-Semantik: Fehlende `required`-Felder sind
    /// kein Fehler, weil der Rest aus dem Bestand kommt — Typ- und
    /// Unknown-Field-Regeln gelten aber weiterhin fuer alles, was
    /// uebergeben wurde.
    ///
    /// Die Details sind sortiert, damit Responses (und Tests)
    /// deterministisch sind. Fehlermeldungen sind reine Client-Payload-
    /// Diagnosen und duerfen an den Client durchgereicht werden.
    pub fn validate(&self, doc: &Value, partial: bool) -> Result<(), Vec<String>> {
        let Some(map) = doc.as_object() else {
            return Err(vec!["payload must be a JSON object".to_string()]);
        };
        let mut errors: Vec<String> = Vec::new();

        if !partial {
            for field in &self.required {
                if !map.contains_key(field) {
                    errors.push(format!("Field '{field}' is required"));
                }
            }
        }

        for (field, expected) in &self.types {
            if let Some(value) = map.get(field) {
                if !expected.matches(value) {
                    errors.push(format!("Field '{field}' must be a {}", expected.as_str()));
                }
            }
        }

        if !self.allow_unknown {
            for field in map.keys() {
                if !self.types.contains_key(field) && !self.required.contains(field) {
                    errors.push(format!(
                        "Field '{field}' is not allowed (unknown fields are rejected)"
                    ));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            errors.sort();
            Err(errors)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_schema(
        required: &[&str],
        types: &[(&str, FieldType)],
        allow_unknown: bool,
    ) -> EndpointSchema {
        EndpointSchema::new(
            required.iter().map(|s| s.to_string()).collect(),
            types
                .iter()
                .map(|(name, ty)| (name.to_string(), *ty))
                .collect(),
            allow_unknown,
        )
    }

    #[test]
    fn field_type_parse_and_match() {
        for (raw, expected) in [
            ("string", FieldType::String),
            ("number", FieldType::Number),
            ("boolean", FieldType::Boolean),
            ("object", FieldType::Object),
            ("array", FieldType::Array),
            ("null", FieldType::Null),
            ("date", FieldType::Date),
            ("datetime", FieldType::DateTime),
        ] {
            assert_eq!(FieldType::parse(raw), Some(expected), "raw={raw}");
            assert_eq!(expected.as_str(), raw);
        }
        assert_eq!(FieldType::parse("int"), None);
        assert_eq!(FieldType::parse("String"), None, "case-sensitiv");
        assert_eq!(FieldType::parse(""), None);

        // JSON hat einen Zahltyp: int und float sind beides number.
        assert!(FieldType::Number.matches(&json!(42)));
        assert!(FieldType::Number.matches(&json!(4.2)));
        assert!(!FieldType::Number.matches(&json!("42")));
        assert!(!FieldType::Number.matches(&json!(true)));
        assert!(FieldType::Object.matches(&json!({})));
        assert!(!FieldType::Array.matches(&json!({})));
    }

    #[test]
    fn date_and_datetime_format_checks() {
        let schema = make_schema(
            &[],
            &[
                ("birthday", FieldType::Date),
                ("starts_at", FieldType::DateTime),
            ],
            true,
        );

        // Gueltige Datumswerte inkl. Schaltjahr (2024, 2000) vs. 1900.
        for good in ["2026-10-23", "2024-02-29", "2000-02-29", "1900-02-28"] {
            assert_eq!(
                schema.validate(&json!({"birthday": good}), false),
                Ok(()),
                "{good}"
            );
        }
        // Ungueltig: Nicht-Schaltjahr, Bereichsverletzungen, nicht
        // gepolstert, falsche Struktur, kein String.
        for bad in [
            "2023-02-29", // kein Schaltjahr
            "2026-13-01", // Monat 13
            "2026-00-10", // Monat 0
            "2026-10-00", // Tag 0
            "2026-10-32", // Tag 32
            "2024-1-1",   // nicht zweistellig gepolstert
            "26-10-23",   // kein vierstelliges Jahr
            "2026/10/23", // falsches Trennzeichen
            "20261023",   // ohne Trennzeichen
        ] {
            let err = schema
                .validate(&json!({ "birthday": bad }), false)
                .unwrap_err();
            assert_eq!(err, vec!["Field 'birthday' must be a date"], "{bad}");
        }
        // Zahl statt String.
        let err = schema
            .validate(&json!({ "birthday": 20261023 }), false)
            .unwrap_err();
        assert_eq!(err, vec!["Field 'birthday' must be a date"]);

        // RFC 3339: Zone ist Pflicht, Schaltsekunde 60 ok, Bruchteile ok,
        // `t`/`z` kleingeschrieben ok (RFC 3339 erlaubt beides).
        for good in [
            "2026-10-23T14:30:00Z",
            "2026-10-23t14:30:00z",
            "2026-10-23T14:30:00.250+02:00",
            "2026-10-23T14:30:00-05:00",
            "2026-06-30T23:59:60Z",
            "2026-10-23T14:30:00.123456789Z",
        ] {
            assert_eq!(
                schema.validate(&json!({ "starts_at": good }), false),
                Ok(()),
                "{good}"
            );
        }
        for bad in [
            "2026-10-23 14:30:00Z",     // Leerzeichen statt T
            "2026-10-23T14:30:00",      // Zone fehlt
            "2026-10-23T14:30Z",        // Sekunden fehlen
            "2026-10-23T24:00:00Z",     // Stunde 24
            "2026-10-23T14:60:00Z",     // Minute 60
            "2026-10-23T14:30:61Z",     // Sekunde 61
            "2026-10-23T14:30:00.",     // Bruchteil ohne Ziffer
            "2026-10-23T14:30:00+0200", // Doppelpunkt im Offset fehlt
            "23.10.2026 14:30",         // deutsches Format
        ] {
            let err = schema
                .validate(&json!({ "starts_at": bad }), false)
                .unwrap_err();
            assert_eq!(err, vec!["Field 'starts_at' must be a datetime"], "{bad}");
        }
        // Zahl statt String.
        let err = schema
            .validate(&json!({ "starts_at": 1_791_744_200 }), false)
            .unwrap_err();
        assert_eq!(err, vec!["Field 'starts_at' must be a datetime"]);
    }

    #[test]
    fn valid_document_with_unknown_fields_passes() {
        let schema = make_schema(
            &["title", "grp"],
            &[
                ("title", FieldType::String),
                ("grp", FieldType::String),
                ("summe", FieldType::Number),
                ("is_priority", FieldType::Boolean),
            ],
            true,
        );
        let doc = json!({
            "title": "Einkaufen",
            "grp": "haushalt",
            "summe": 42.5,
            "is_priority": false,
            "notiz": "freies Feld",
            "tags": ["a", "b"]
        });
        assert_eq!(schema.validate(&doc, false), Ok(()));
    }

    #[test]
    fn missing_required_and_wrong_types_are_all_reported() {
        let schema = make_schema(
            &["title", "grp"],
            &[
                ("title", FieldType::String),
                ("grp", FieldType::String),
                ("summe", FieldType::Number),
                ("is_priority", FieldType::Boolean),
            ],
            true,
        );
        let doc = json!({
            "title": 7,
            "summe": "keine zahl",
            "is_priority": "ja",
            "extra": true
        });
        let err = schema.validate(&doc, false).unwrap_err();
        // Deterministisch sortiert; fehlende UND typfremde Felder stehen
        // gemeinsam in den Details.
        assert_eq!(
            err,
            vec![
                "Field 'grp' is required",
                "Field 'is_priority' must be a boolean",
                "Field 'summe' must be a number",
                "Field 'title' must be a string",
            ]
        );
    }

    #[test]
    fn unknown_fields_are_rejected_in_strict_mode() {
        let schema = make_schema(&["title"], &[("title", FieldType::String)], false);
        let err = schema
            .validate(&json!({"title": "ok", "surprise": 1}), false)
            .unwrap_err();
        assert_eq!(
            err,
            vec!["Field 'surprise' is not allowed (unknown fields are rejected)"]
        );

        // Deklarierte Felder (required oder types) gelten nicht als unknown.
        let schema = make_schema(&["title"], &[("note", FieldType::String)], false);
        assert_eq!(
            schema.validate(&json!({"title": "ok", "note": "x"}), false),
            Ok(())
        );
    }

    #[test]
    fn optional_typed_fields_may_be_absent_but_not_wrong() {
        // `summe` ist nicht required: Fehlen ist ok, falscher Typ nicht.
        let schema = make_schema(&["title"], &[("summe", FieldType::Number)], true);
        assert_eq!(schema.validate(&json!({"title": "x"}), false), Ok(()));
        let err = schema
            .validate(&json!({"title": "x", "summe": [1]}), false)
            .unwrap_err();
        assert_eq!(err, vec!["Field 'summe' must be a number"]);
    }

    #[test]
    fn null_semantics_follow_json_schema_conventions() {
        // Explizites null zaehlt als vorhanden (required erfuellt), gegen
        // einen deklarierten Typ verletzt es diesen aber — so bleibt
        // `types` die schwaechste Aussagekraft erhalten.
        let schema = make_schema(&["note"], &[("summe", FieldType::Number)], true);
        assert_eq!(schema.validate(&json!({"note": null}), false), Ok(()));
        let err = schema
            .validate(&json!({"note": null, "summe": null}), false)
            .unwrap_err();
        assert_eq!(err, vec!["Field 'summe' must be a number"]);
    }

    #[test]
    fn patch_partial_skips_required_but_keeps_types_and_unknown() {
        let schema = make_schema(
            &["title", "grp"],
            &[
                ("title", FieldType::String),
                ("grp", FieldType::String),
                ("summe", FieldType::Number),
            ],
            true,
        );

        // Partieller Patch ohne ein einziges required-Feld: valide.
        assert_eq!(schema.validate(&json!({"summe": 5}), true), Ok(()));

        // Typ-Regel greift im Patch weiterhin.
        let err = schema.validate(&json!({"title": 9}), true).unwrap_err();
        assert_eq!(err, vec!["Field 'title' must be a string"]);

        // Unknown-Field-Regel ebenso (Strikt-Schema, sonst wird `neu`
        // mangels `allow_unknown_fields = false` durchgewunken).
        let strict = make_schema(&[], &[("summe", FieldType::Number)], false);
        let err = strict.validate(&json!({"neu": 1}), true).unwrap_err();
        assert_eq!(
            err,
            vec!["Field 'neu' is not allowed (unknown fields are rejected)"]
        );

        // Und required wird im Vollmodus (POST/PUT) weiterhin geprueft.
        let err = schema.validate(&json!({"summe": 5}), false).unwrap_err();
        assert_eq!(
            err,
            vec!["Field 'grp' is required", "Field 'title' is required"]
        );
    }

    #[test]
    fn duplicate_required_entries_are_deduplicated() {
        let schema = make_schema(&["title", "title"], &[], true);
        assert_eq!(schema.required().len(), 1);
        // Fehlendes Feld erzeugt genau EINE Meldung.
        assert_eq!(
            schema.validate(&json!({}), false),
            Err(vec!["Field 'title' is required".to_string()])
        );
    }

    #[test]
    fn non_object_documents_are_rejected() {
        let schema = make_schema(&[], &[], true);
        for doc in [json!(null), json!([]), json!("x"), json!(1)] {
            assert!(schema.validate(&doc, false).is_err(), "{doc}");
        }
    }

    #[test]
    fn schema_new_clones_are_cheap_and_read_only() {
        // Der Arc-geteilte Runtime-Bau: Clone teilt nichts Beobachtbares
        // anders als die Werte selbst — hier nur Verhaltenssicherung.
        let schema = make_schema(&["a"], &[("a", FieldType::String)], false);
        let copy = schema.clone();
        assert_eq!(copy.validate(&json!({"a": "x"}), false), Ok(()));
    }
}
