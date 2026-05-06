import sqlite3
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "ids_alerts.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            module_source TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL,
            threat_score REAL,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            details TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_alert(
    module_source,
    attack_type,
    severity,
    confidence=None,
    threat_score=None,
    src_ip=None,
    dst_ip=None,
    protocol=None,
    details=None
):
    init_db()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts (
            timestamp,
            module_source,
            attack_type,
            severity,
            confidence,
            threat_score,
            src_ip,
            dst_ip,
            protocol,
            details
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        module_source,
        attack_type,
        severity,
        confidence,
        threat_score,
        src_ip,
        dst_ip,
        protocol,
        details
    ))

    conn.commit()
    conn.close()


def save_alerts_bulk(alerts):
    init_db()

    conn = get_connection()
    cursor = conn.cursor()

    rows = []

    for alert in alerts:
        rows.append((
            alert.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            alert.get("module_source", "Unknown"),
            alert.get("attack_type", "Unknown"),
            alert.get("severity", "UNKNOWN"),
            alert.get("confidence"),
            alert.get("threat_score"),
            alert.get("src_ip"),
            alert.get("dst_ip"),
            alert.get("protocol"),
            alert.get("details")
        ))

    cursor.executemany("""
        INSERT INTO alerts (
            timestamp,
            module_source,
            attack_type,
            severity,
            confidence,
            threat_score,
            src_ip,
            dst_ip,
            protocol,
            details
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, rows)

    conn.commit()
    conn.close()


def get_all_alerts(limit=500):
    init_db()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM alerts
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]


def get_alert_count():
    init_db()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM alerts")
    count = cursor.fetchone()[0]

    conn.close()
    return count