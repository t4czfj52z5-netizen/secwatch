# secwatch – IT-Sicherheitsdigest (2× täglich)

Sammelt aktuelle Sicherheitsvorfälle und Störungen zu gewählten IT-Themen
(Microsoft, CGM/CompuGroup Medical, Tanium, …) aus RSS/Atom-Newsfeeds,
Foren-Blogs und maschinenlesbaren Quellen (CISA KEV), filtert nach deinen
Stichworten, bewertet die Dringlichkeit und stellt das Ergebnis 2× täglich
als Digest zu (Datei, E-Mail via SMTP oder Webhook z. B. Teams/Slack/Telegram).

Nur Python-Standardbibliothek nötig (Python 3.9+).

## Einrichtung

```bash
cp config.example.json config.json
# config.json anpassen: feeds, watch-Stichworte, delivery
python3 secwatch.py --config config.json --dry-run   # Testlauf, zeigt Digest auf stdout
```

## 2× täglich ausführen (z. B. 08:00 und 17:00 Uhr)

cron:

```
0 8,17 * * * cd /opt/secwatch && /usr/bin/python3 secwatch.py --config config.json >> secwatch.log 2>&1
```

systemd-Timer (alternativ): `secwatch.service` + `secwatch.timer` mit
`OnCalendar=*-*-* 08:00,17:00`.

GitHub Actions (läuft kostenlos ohne eigenen Server), Datei
`.github/workflows/digest.yml`:

```yaml
name: IT-Sicherheitsdigest
on:
  schedule:
    - cron: "0 6,15 * * *"   # 08:00 und 17:00 MEZ (UTC+1) bzw. 08:00/17:00 MESZ
  workflow_dispatch:
jobs:
  digest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python3 secwatch.py --config config.json
        env:
          DIGEST_WEBHOOK_URL: ${{ secrets.DIGEST_WEBHOOK_URL }}
          SMTP_PASSWORD: ${{ secrets.SMTP_PASSWORD }}
```

Das Zeitfenster je Lauf ist "seit letztem Lauf" (State in `secwatch.db`),
default `default_since_hours`. Deduplizierung über GUIDs – keine Doppelmeldungen.

## Zustellung konfigurieren (`delivery` in config.json)

- `{"type": "file", "output_dir": "digests"}` – schreibt `digest_YYYYMMDD_HHMM.md/.html`
- `{"type": "smtp", "smtp": {"host": "...", "port": 587, "use_starttls": true, "user": "...", "from": "...", "to": ["du@example.de"], "password_env": "SMTP_PASSWORD"}}` – Passwort nur als Umgebungsvariable
- `{"type": "webhook", "url_env": "DIGEST_WEBHOOK_URL", "format": "json"|"slack"}` – URL nur als Umgebungsvariable (Repo-Secret bei GitHub Actions)

## Quellen & Filter

- `feeds`: RSS/Atom (`type: rss|atom`) oder CISA-KEV-JSON (`type: kev`).
  Feeds mit `"always": true` landen immer im Digest (z. B. Hersteller-Advisories
  von Tanium/CGM/MSRC); alle anderen nur bei Stichwort-Treffer.
- `watch`: Themen → Stichwortliste (case-insensitive, Titel + Beschreibung).
  Weitere Hersteller einfach als eigenes Thema ergänzen.
- Bewertung: CISA-KEV-Eintrag = 100 Punkte, Ransomware +25, Zero-day/aktiv
  ausgenutzt/Outage/Ransomware/Critical … += Punkte; danach sortiert.
  Schwellen: ab 60 "Kritisch", ab 25 "Hoch", sonst "Info".

## Sicherheit

- Keine Secrets in `config.json` – nur Umgebungsvariablen (`SMTP_PASSWORD`,
  `DIGEST_WEBHOOK_URL`) bzw. GitHub-Secrets.
- Ausgehende Verbindungen nur zu den konfigurierten Feed-URLs (HTTPS).
- Fehler einzelner Feeds werden protokolliert und übersprungen, der Lauf
  bricht dadurch nicht ab.

## Troubleshooting

- `--dry-run` schreibt keinen State und sendet nichts.
- `--since-hours N` überschreibt das Zeitfenster (z. B. erster Lauf: `--since-hours 48`).
- Feed antwortet nicht/404: URL in `config.json` prüfen, Eintrag vorübergehend entfernen.
- Logs landen auf stderr (`secwatch.log` bei cron).
- Lokaler Smoke-Test ohne Netzwerk: `python3 secwatch.py --config tests/test_config.json --dry-run`
