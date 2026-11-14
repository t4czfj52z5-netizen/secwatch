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
