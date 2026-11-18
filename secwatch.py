#!/usr/bin/env python3

import argparse
import hashlib
import html as html_lib
import json
import os
import re
import smtplib
import sqlite3
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import parsedate_to_datetime
from pathlib import Path
from xml.etree import ElementTree as ET

ATOM = "{http://www.w3.org/2005/Atom}"
DC = "{http://purl.org/dc/elements/1.1/}"
CONTENT = "{http://purl.org/rss/1.0/modules/content/}"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
USER_AGENT = "secwatch/1.0 (local IT security digest)"

SEVERITY_KEYWORDS = [
    ("zero-day", 30),
    ("0-day", 30),
    ("zero day", 30),
    ("actively exploited", 30),
    ("exploited in the wild", 30),
    ("ransomware", 25),
    ("outage", 25),
    ("störung", 25),
    ("stoerung", 25),
    ("ausfall", 25),
    ("cyberattack", 20),
    ("cyberangriff", 20),
    ("hackerangriff", 20),
    ("security breach", 20),
    ("data breach", 20),
    ("supply chain", 20),
    ("critical", 15),
    ("sicherheitslücke", 15),
    ("schwachstelle", 15),
    ("widespread", 10),
    ("massive", 10),
    ("weltweit", 10),
    ("worldwide", 10),
]


def log(msg):
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    print(f"[{stamp}] {msg}", file=sys.stderr)


def parse_date(raw):
    if not raw:
        return None
    raw = raw.strip()
    try:
        return parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        pass
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def fetch(url, timeout):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/rss+xml, application/atom+xml, application/json, text/xml, */*",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def child_text(elem, *tags):
    for tag in tags:
        found = elem.find(tag)
        if found is not None and found.text:
            return found.text.strip()
    return ""


def parse_feed(data):
    root = ET.fromstring(data)
    items = []
    if root.tag.endswith("rss"):
        channel = root.find("channel")
        entries = channel.findall("item") if channel is not None else []
        for it in entries:
            link = child_text(it, "link")
            items.append({
                "guid": child_text(it, "guid") or link,
                "title": child_text(it, "title"),
                "link": link,
                "summary": child_text(it, "description", f"{CONTENT}encoded", "summary"),
                "published": parse_date(child_text(it, "pubDate", f"{DC}date")),
            })
    elif root.tag == f"{ATOM}feed":
        for entry in root.findall(f"{ATOM}entry"):
            link = ""
            for l in entry.findall(f"{ATOM}link"):
                if l.get("rel") in (None, "alternate") and l.get("href"):
                    link = l.get("href")
                    break
            items.append({
                "guid": child_text(entry, f"{ATOM}id") or link,
                "title": child_text(entry, f"{ATOM}title"),
                "link": link,
                "summary": child_text(entry, f"{ATOM}summary", f"{ATOM}content"),
                "published": parse_date(child_text(entry, f"{ATOM}published", f"{ATOM}updated")),
            })
    return items


def parse_kev(data):
    doc = json.loads(data)
    items = []
    for v in doc.get("vulnerabilities", []):
        cve = v.get("cveID", "")
        title = f"{cve} – {v.get('vendorProject', '')} {v.get('product', '')}".replace("  ", " ").strip(" –")
        items.append({
            "guid": f"kev:{cve}:{v.get('dateAdded', '')}",
            "title": title,
            "link": v.get("url", ""),
            "summary": v.get("shortDescription", ""),
            "published": parse_date(v.get("dateAdded", "")),
            "kev": True,
            "ransomware": v.get("knownRansomwareCampaignUse", "") == "Known",
        })
    return items


def score_item(text, is_kev=False, ransomware=False):
    low = text.lower()
    score = 100 if is_kev else 0
    if ransomware:
        score += 25
    for kw, pts in SEVERITY_KEYWORDS:
        if kw in low:
            score += pts
    score += min(len(CVE_RE.findall(text)), 3) * 5
    return score


def bucket(score):
    if score >= 60:
        return "Kritisch"
    if score >= 25:
        return "Hoch"
    return "Info"


def open_db(path):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE IF NOT EXISTS seen (guid TEXT PRIMARY KEY, seen_at TEXT NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.commit()
    return conn


def is_seen(conn, guid):
    return conn.execute("SELECT 1 FROM seen WHERE guid = ?", (guid,)).fetchone() is not None


def mark_seen(conn, guid):
    conn.execute(
        "INSERT OR IGNORE INTO seen (guid, seen_at) VALUES (?, ?)",
        (guid, datetime.now(timezone.utc).isoformat(timespec="seconds")),
    )
    conn.commit()


def get_meta(conn, key):
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def set_meta(conn, key, value):
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))
    conn.commit()


def collect(cfg, since, conn):
    watch = {t: [k.lower() for k in kws] for t, kws in cfg.get("watch", {}).items()}
    results = []
    for feed in cfg.get("feeds", []):
        url = feed["url"]
        name = feed.get("name", url)
        ftype = feed.get("type", "rss")
        try:
            data = fetch(url, timeout=feed.get("timeout", 30))
            parsed = parse_kev(data) if ftype == "kev" else parse_feed(data)
        except Exception as exc:
            log(f"feed failed: {name} ({url}): {exc}")
            continue
        for it in parsed:
            text = f"{it.get('title', '')} {it.get('summary', '')}"
            low = text.lower()
            topics = [t for t, kws in watch.items() if any(k in low for k in kws)]
            if not feed.get("always") and not topics:
                continue
            pub = it.get("published")
            if pub is not None and pub < since:
                continue
            guid = it.get("guid") or it.get("link") or hashlib.sha1(it.get("title", "").encode()).hexdigest()
            if is_seen(conn, guid):
                continue
            score = score_item(text, it.get("kev", False), it.get("ransomware", False))
            results.append({
                "title": it.get("title", "(ohne Titel)"),
                "link": it.get("link", ""),
                "summary": it.get("summary", ""),
                "source": name,
                "published": pub.isoformat() if pub else "",
                "topics": topics or [feed.get("topic", name)],
                "score": score,
                "guid": guid,
            })
    results.sort(key=lambda x: x["score"], reverse=True)
    return results


def clean(text, limit=220):
    return re.sub(r"\s+", " ", text or "")[:limit]


def render_md(items, since, generated):
    lines = [
        f"# IT-Sicherheitsdigest – {generated:%d.%m.%Y %H:%M} UTC",
        f"_Zeitfenster: seit {since:%d.%m.%Y %H:%M} UTC · {len(items)} Meldungen_",
        "",
    ]
    if not items:
        lines.append("_Keine neuen relevanten Meldungen im Zeitfenster._")
    for b in ("Kritisch", "Hoch", "Info"):
        group = [i for i in items if bucket(i["score"]) == b]
        if not group:
            continue
        lines.append(f"## {b} ({len(group)})")
        for i in group:
            link = f"[{i['title']}]({i['link']})" if i["link"] else i["title"]
            summary = clean(i["summary"])
            lines.append(f"- {link} — *{', '.join(i['topics'])}* — {i['source']} (Score {i['score']})")
            if summary:
                lines.append(f"  - {summary}")
        lines.append("")
    return "\n".join(lines) + "\n"


def render_html(items, since, generated):
    esc = html_lib.escape
    parts = [
        f"<h1>IT-Sicherheitsdigest – {generated:%d.%m.%Y %H:%M} UTC</h1>",
        f"<p>Zeitfenster: seit {since:%d.%m.%Y %H:%M} UTC · {len(items)} Meldungen</p>",
    ]
    if not items:
        parts.append("<p>Keine neuen relevanten Meldungen im Zeitfenster.</p>")
    for b in ("Kritisch", "Hoch", "Info"):
        group = [i for i in items if bucket(i["score"]) == b]
        if not group:
            continue
        parts.append(f"<h2>{b} ({len(group)})</h2><ul>")
        for i in group:
            link = f'<a href="{esc(i["link"])}">{esc(i["title"])}</a>' if i["link"] else esc(i["title"])
            parts.append(
                f"<li>{link} — <em>{esc(', '.join(i['topics']))}</em> — {esc(i['source'])} "
                f"(Score {i['score']})<br><small>{esc(clean(i['summary']))}</small></li>"
            )
        parts.append("</ul>")
    return "<html><body>" + "\n".join(parts) + "</body></html>"


def deliver(cfg, subject, md, html, items):
    d = cfg.get("delivery", {})
    dtype = d.get("type", "file")
    if dtype == "file":
        outdir = Path(d.get("output_dir", "digests"))
        outdir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
        (outdir / f"digest_{stamp}.md").write_text(md, encoding="utf-8")
        (outdir / f"digest_{stamp}.html").write_text(html, encoding="utf-8")
        log(f"digest written to {outdir}/digest_{stamp}.md|.html")
        return
    if dtype == "smtp":
        s = d["smtp"]
        to = s["to"] if isinstance(s["to"], list) else [s["to"]]
        password = os.environ.get(s.get("password_env", "SMTP_PASSWORD"), "")
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = s["from"]
        msg["To"] = ", ".join(to)
        msg.attach(MIMEText(md, "plain", "utf-8"))
        msg.attach(MIMEText(html, "html", "utf-8"))
        with smtplib.SMTP(s["host"], s.get("port", 587), timeout=30) as server:
            if s.get("use_starttls", True):
                server.starttls()
            if s.get("user"):
                server.login(s["user"], password)
            server.sendmail(s["from"], to, msg.as_string())
        log(f"digest sent via SMTP to {', '.join(to)}")
        return
    if dtype == "webhook":
        url = os.environ.get(d.get("url_env", "DIGEST_WEBHOOK_URL"), "")
        if not url:
            raise RuntimeError(f"webhook URL missing: set env var {d.get('url_env', 'DIGEST_WEBHOOK_URL')}")
                max_len = int(d.get("max_text_length", 4000))
        text = md if len(md) <= max_len else md[: max_len - 80] + "\n… (gekürzt – vollständiger Digest im Artifact)"
        if d.get("format") == "slack":
            payload = {"text": f"*{subject}*\n{text}"}
        else:
            payload = {
                "subject": subject,
                "text": text,
                "items": [
                    {k: i[k] for k in ("title", "link", "summary", "source", "topics", "score", "published")}
                    for i in items
                ],
            }
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp.read()
        log("digest sent via webhook")
        return
    raise ValueError(f"unknown delivery type: {dtype}")


def main():
    ap = argparse.ArgumentParser(description="IT-Sicherheitsdigest aus RSS/Atom/CISA-KEV-Quellen")
    ap.add_argument("--config", default="config.json")
    ap.add_argument("--state", default=None)
    ap.add_argument("--since-hours", type=float, default=None)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
    base = Path(args.config).resolve().parent
    for feed in cfg.get("feeds", []):
        url = feed["url"]
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
            feed["url"] = (base / url).as_uri()
    state = args.state or cfg.get("state_file", "secwatch.db")
    conn = open_db(state)

    now = datetime.now(timezone.utc)
    if args.since_hours is not None:
        since = now - timedelta(hours=args.since_hours)
    else:
        last = get_meta(conn, "last_run")
        parsed_last = parse_date(last) if last else None
        since = parsed_last or now - timedelta(hours=cfg.get("default_since_hours", 12))

    items = collect(cfg, since, conn)
    limit = args.limit or cfg.get("limit", 25)
    items = items[:limit]

    critical = sum(1 for i in items if bucket(i["score"]) == "Kritisch")
    subject = f"IT-Sicherheitsdigest {now:%d.%m.%Y %H:%M} UTC – {len(items)} Meldungen ({critical} kritisch)"
    md = render_md(items, since, now)
    html = render_html(items, since, now)

    if args.dry_run:
        print(md)
    else:
        deliver(cfg, subject, md, html, items)
        for i in items:
            mark_seen(conn, i["guid"])
        set_meta(conn, "last_run", now.isoformat(timespec="seconds"))
        log(f"done: {len(items)} new item(s) processed")


if __name__ == "__main__":
    main()
