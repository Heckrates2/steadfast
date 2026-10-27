//! Periodische Bereinigung fuer alle aktiven App-Auths: loescht abgelaufene
//! Refresh-Token-Dokumente (nach Ablauf der Evidence-Frist) und leer
//! gelaufene Rate-Limit-Buckets. Ein Task fuer alle Apps, alle 10 Minuten.

use std::sync::Arc;
use std::time::Duration;

use crate::AppAuth;

/// Standard-Intervall des Sweepers.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(600);

/// Startet den Sweeper-Task (endet nie; stirbt mit dem Prozess bzw. beim
/// Runtime-Shutdown). `interval` ist Parameter, damit Tests schnell ticken
/// koennen — Produktion uebergibt [`SWEEP_INTERVAL`] (macht `main`).
pub fn spawn_sweeper(auths: Vec<Arc<AppAuth>>, interval: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            for auth in &auths {
                auth.sweep();
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_app_auth;
    use crate::tokens::generate_refresh_token;
    use crate::tokens::refresh_hash;
    use serde_json::json;

    /// Der Sweeper muss tatsaechlich arbeiten: ein stale Token verschwindet
    /// nach dem ersten Tick (Polling statt blindem Sleep, siehe
    /// wal_persistence-Tests).
    #[tokio::test]
    async fn sweeper_cleans_stale_refresh_tokens() {
        let auth = Arc::new(test_app_auth());
        let stale = generate_refresh_token();
        auth.store()
            .create(
                "demo",
                crate::REFRESH_COLLECTION,
                &refresh_hash(&stale),
                json!({
                    "user_id": "u_x", "created_at": 0, "expires_at": 1,
                    "revoked": false, "replaced_by": serde_json::Value::Null,
                    "revoked_at": 0,
                }),
            )
            .unwrap();
        assert!(
            auth.store()
                .get("demo", crate::REFRESH_COLLECTION, &refresh_hash(&stale))
                .is_some()
        );

        let handle = spawn_sweeper(vec![Arc::clone(&auth)], Duration::from_millis(10));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if auth
                .store()
                .get("demo", crate::REFRESH_COLLECTION, &refresh_hash(&stale))
                .is_none()
            {
                handle.abort();
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        handle.abort();
        panic!("Sweeper hat das abgelaufene Token nicht entfernt");
    }
}
