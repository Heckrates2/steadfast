# Steadfast Security-Policy

## Unterstützte Versionen

Security-Fixes landen im `main`-Branch; es gibt (noch) keine versionierten
Releases. Halte den Checkout aktuell.

## Melden einer Schwachstelle

**Bitte erstelle KEIN öffentliches GitHub-Issue für Sicherheitslücken.**

Melde Schwachstellen stattdessen vertraulich:

1. **Bevorzugt:** GitHub → Security → "Report a vulnerability" (private
   Vulnerability-Reporting des Repos).
2. **Alternativ:** E-Mail an die in den Repository-Metadaten hinterlegte
   Security-Adresse mit dem Betreff `[security] <Kurzbeschreibung>`.

Bitte liefere mit: betroffene Komponente (`steadfast-server`, `steadfast-core`,
`steadfast-storage`), Reproduktionsschritte oder PoC, eingesetzte Konfiguration
(`apps.toml`, Startargumente, `ENGINE_GATEWAY_SECRET` aktiv?) und deine
Einschätzung der Auswirkungen.

## Umgang mit Meldungen

- Bestätigung des Erhalts innerhalb von **7 Tagen**.
- Bewertung und Kommunikationstermin werden individuell vereinbart; als
   Richtwert gilt **90 Tage** bis zur Veröffentlichung (koordinated
   disclosure).
- Credits auf Wunsch in der Release-/Commit-Notiz.

## Scope

Die Engine ist als **Open-Source-Komponente hinter einem Gateway** gebaut
(siehe `SECURITY_AUDIT_V2.md` und README "Security-Modell"): User-Auth,
Rate-Limiting und TLS liegen beim Betreiber. Gemeldet werden sollte alles,
was die Engine selbst betrifft — etwa Sandbox-Escapes (Rhai), Auth-Bypass
(`X-API-Key`), Header-Spoofing (`X-User-*`, `X-Internal-Auth`), Datenkorruption
(WAL/Snapshot) oder Injection in Filter/Sortierung.

Außer Scope: Fehlkonfigurationen ohne Code-Verantwortung (z. B. fehlende
Netzwerk-Isolation des Engine-Ports, im Klartext committe Secrets, fehlende
Gateway-Rate-Limits) — dafür dokumentiert das Security-Modell die
Betreiber-Verantwortung.

## Bekannte bewusste Grenzen

Diese Punkte sind dokumentiert und bewusst (siehe Audit-Report):

- Kein Audit-Trail (Phase 3).
- Ohne gesetztes `ENGINE_GATEWAY_SECRET` werden `X-User-*`-Header
  unverifiziert honoring (Gateway-Vertrauensmodell).
- Rate-Limiting/Timeouts liegen beim Gateway.
