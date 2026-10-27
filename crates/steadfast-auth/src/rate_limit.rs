//! Token-Bucket-Rate-Limiting fuer die Auth-Endpunkte, je Client-IP und App
//! (der Limiter lebt im [`crate::AppAuth`] der App). Brutte-Force-Schutz
//! auf `login`/`register`/`refresh` — die Daten-Endpunkte bleiben wie
//! dokumentiert ohne Rate-Limit (dafuer ist das Gateway zustaendig).
//!
//! Bucket-Modell: Capacity = konfigurierter Wert pro Minute, Auffuellung
//! proportional (Wert/60 pro Sekunde). Ein Ruck von `login_per_min`
//! Versuchen ist sofort moeglich, danach daempft die Auffuellung. IPs ohne
//! Peer-Adresse (Tests, Embeddings ohne ConnectInfo) teilen sich den
//! Bucketschluessel "unknown".

use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use dashmap::DashMap;
use steadfast_core::AuthRateLimit;

/// Was limiting sein soll — Map auf die konfigurierten Werte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Login,
    Register,
    Refresh,
}

impl Kind {
    fn key_segment(self) -> &'static str {
        match self {
            Kind::Login => "login",
            Kind::Register => "register",
            Kind::Refresh => "refresh",
        }
    }

    fn per_min(self, settings: &AuthRateLimit) -> u64 {
        match self {
            Kind::Login => settings.login_per_min,
            Kind::Register => settings.register_per_min,
            Kind::Refresh => settings.refresh_per_min,
        }
    }
}

/// Ein Bucket: aktueller Stand plus Füllparameter. `Mutex` pro Bucket —
/// Kontention ausschliesslich auf derselben IP + dieselbem Endpunkt.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    capacity: f64,
    refill_per_sec: f64,
    last: Instant,
}

#[derive(Debug, Default)]
pub(crate) struct RateLimiter {
    buckets: DashMap<String, Mutex<Bucket>>,
}

impl RateLimiter {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Zieht ein Token; bei leerem Bucket bleibt nur die Antwortzeit.
    /// `Ok(())` = erlaubt, `Err(sekunden)` = 429 mit `Retry-After`.
    pub(crate) fn check(
        &self,
        kind: Kind,
        ip: Option<IpAddr>,
        settings: &AuthRateLimit,
    ) -> Result<(), u64> {
        let per_min = kind.per_min(settings).max(1);
        let key = match ip {
            Some(ip) => format!("{}:{ip}", kind.key_segment()),
            None => format!("{}:unknown", kind.key_segment()),
        };
        let start = Instant::now();

        let mut entry = self.buckets.entry(key).or_insert_with(|| {
            Mutex::new(Bucket {
                tokens: per_min as f64,
                capacity: per_min as f64,
                refill_per_sec: per_min as f64 / 60.0,
                last: start,
            })
        });
        let bucket = entry.get_mut().expect("Bucket-Mutex");
        let elapsed = start.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.last = start;
        bucket.tokens = (bucket.tokens + elapsed * bucket.refill_per_sec).min(bucket.capacity);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            let missing = 1.0 - bucket.tokens;
            Err((missing / bucket.refill_per_sec).ceil().max(1.0) as u64)
        }
    }

    /// Sweeper: Buckets entfernen, die seit 15 Minuten niemand angefasst
    /// hat (volle Buckets von Offline-IPs verstopfen sonst den Speicher).
    pub(crate) fn sweep(&self) {
        self.buckets.retain(|_, bucket| {
            bucket
                .get_mut()
                .map(|b| b.last.elapsed() < Duration::from_secs(900))
                .unwrap_or(true)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(login: u64) -> AuthRateLimit {
        AuthRateLimit {
            login_per_min: login,
            register_per_min: login,
            refresh_per_min: login,
        }
    }

    fn ip(a: u8) -> Option<IpAddr> {
        Some(format!("127.0.0.{a}").parse().unwrap())
    }

    #[test]
    fn burst_exhausts_then_throttles() {
        let limiter = RateLimiter::new();
        let settings = settings(3);
        for _ in 0..3 {
            assert!(limiter.check(Kind::Login, ip(1), &settings).is_ok());
        }
        let retry = limiter.check(Kind::Login, ip(1), &settings).unwrap_err();
        assert!(
            (1..=20).contains(&retry),
            "Retry-After im sinnvollen Rahmen: {retry}"
        );
    }

    #[test]
    fn ips_and_kinds_are_independent_buckets() {
        let limiter = RateLimiter::new();
        let settings = settings(2);
        for _ in 0..2 {
            assert!(limiter.check(Kind::Login, ip(1), &settings).is_ok());
        }
        assert!(limiter.check(Kind::Login, ip(1), &settings).is_err());
        // Andere IP: eigener Bucket.
        assert!(limiter.check(Kind::Login, ip(2), &settings).is_ok());
        // Anderer Endpunkt auf derselben IP: eigener Bucket.
        assert!(limiter.check(Kind::Refresh, ip(1), &settings).is_ok());
        // Ohne IP: gemeinsamer "unknown"-Bucket.
        assert!(limiter.check(Kind::Login, None, &settings).is_ok());
    }

    #[test]
    fn sweep_drops_idle_buckets() {
        let limiter = RateLimiter::new();
        let settings = settings(1);
        assert!(limiter.check(Kind::Login, ip(9), &settings).is_ok());
        assert_eq!(limiter.buckets.len(), 1);

        // Idle-Zeit simulieren: last auf vor 20 Minuten zurueckdrehen.
        let key = limiter.buckets.iter().next().unwrap().key().clone();
        {
            let entry = limiter.buckets.get_mut(&key).unwrap();
            let mut bucket = entry.lock().unwrap();
            bucket.last = Instant::now() - Duration::from_secs(1200);
        }
        limiter.sweep();
        assert!(limiter.buckets.is_empty(), "Idle-Bucket entfernt");
    }
}
