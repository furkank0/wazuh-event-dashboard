#!/usr/bin/env python3
import sys
import json
import sqlite3
import os
from datetime import datetime

DB_PATH = "/opt/wazuh-dashboard/events.db"

EVENT_MAP = {
    "4624": {"category": "login_success",   "label": "Başarılı Giriş",               "severity": "info"},
    "4625": {"category": "login_fail",      "label": "Başarısız Giriş",              "severity": "warning"},
    "4634": {"category": "logoff",          "label": "Oturum Kapatıldı",             "severity": "info"},
    "4647": {"category": "logoff",          "label": "Oturum Kapatıldı",             "severity": "info"},
    "4648": {"category": "login_explicit",  "label": "Explicit Credential Girişi",   "severity": "warning"},
    "4672": {"category": "admin_login",     "label": "Yönetici Girişi",              "severity": "warning"},
    "4720": {"category": "account_created", "label": "Hesap Oluşturuldu",            "severity": "critical"},
    "4726": {"category": "account_deleted", "label": "Hesap Silindi",                "severity": "critical"},
    "4740": {"category": "account_locked",  "label": "Hesap Kilitlendi",             "severity": "critical"},
    "4767": {"category": "account_unlocked","label": "Hesap Kilidi Açıldı",          "severity": "warning"},
    "4728": {"category": "group_change",    "label": "Gruba Üye Eklendi (Global)",   "severity": "critical"},
    "4732": {"category": "group_change",    "label": "Gruba Üye Eklendi (Local)",    "severity": "critical"},
    "4756": {"category": "group_change",    "label": "Gruba Üye Eklendi (Universal)","severity": "critical"},
    "7045": {"category": "new_service",     "label": "Yeni Servis Kuruldu",          "severity": "critical"},
    "4698": {"category": "scheduled_task",  "label": "Scheduled Task Oluşturuldu",   "severity": "critical"},
    "4702": {"category": "scheduled_task",  "label": "Scheduled Task Güncellendi",   "severity": "warning"},
    "4688": {"category": "process_created", "label": "Yeni Süreç Başlatıldı",        "severity": "info"},
    "4689": {"category": "process_exit",    "label": "Süreç Sonlandı",               "severity": "info"},
    "4776": {"category": "credential_val",  "label": "Kimlik Doğrulama Denemesi",    "severity": "info"},
    "4771": {"category": "kerb_fail",       "label": "Kerberos Ön-Doğrulama Başarısız","severity": "warning"},
}

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            server      TEXT NOT NULL,
            event_id    TEXT NOT NULL,
            category    TEXT NOT NULL,
            label       TEXT NOT NULL,
            severity    TEXT NOT NULL,
            username    TEXT,
            source_ip   TEXT,
            raw_data    TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_severity  ON events(severity)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_category  ON events(category)")
    conn.commit()
    conn.close()

def parse_alert(alert_data):
    win      = alert_data.get("data", {}).get("win", {})
    sys_data = win.get("system", {})
    evt_data = win.get("eventdata", {})

    event_id = str(sys_data.get("eventID", "") or alert_data.get("data", {}).get("id", ""))

    event_info = EVENT_MAP.get(event_id, {
        "category": "other",
        "label":    f"Event {event_id}",
        "severity": "info"
    })

    username = (
        evt_data.get("targetUserName") or
        evt_data.get("subjectUserName") or
        alert_data.get("data", {}).get("dstuser") or
        "-"
    )

    source_ip = (
        evt_data.get("ipAddress") or
        evt_data.get("workstationName") or
        alert_data.get("data", {}).get("srcip") or
        "-"
    )

    return {
        "timestamp": alert_data.get("timestamp", datetime.utcnow().isoformat()),
        "server":    alert_data.get("agent", {}).get("name", "unknown"),
        "event_id":  event_id,
        "category":  event_info["category"],
        "label":     event_info["label"],
        "severity":  event_info["severity"],
        "username":  username,
        "source_ip": source_ip,
        "raw_data":  json.dumps(alert_data, ensure_ascii=False),
    }

def save_event(event):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO events
            (timestamp, server, event_id, category, label, severity, username, source_ip, raw_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event["timestamp"], event["server"],    event["event_id"],
        event["category"],  event["label"],     event["severity"],
        event["username"],  event["source_ip"], event["raw_data"],
    ))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    try:
        with open(sys.argv[1]) as f:
            alert_data = json.load(f)
        event = parse_alert(alert_data)
        if event["event_id"] in EVENT_MAP:
            save_event(event)
    except Exception as e:
        with open("/var/ossec/logs/integrations.log", "a") as log:
            log.write(f"{datetime.utcnow().isoformat()} [wazuh_to_db] ERROR: {e}\n")
