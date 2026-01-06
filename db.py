from datetime import datetime, timezone
import json

import psycopg
from psycopg.types.json import Json

from config import DATABASE_URL, SUBSCRIBERS_FILE


def get_conn() -> psycopg.Connection:
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set.")
    return psycopg.connect(DATABASE_URL)


def ensure_schema(conn: psycopg.Connection) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                title TEXT,
                link TEXT,
                description TEXT,
                published_at TIMESTAMPTZ,
                rss_raw JSONB,
                circl_raw JSONB,
                nvd_raw JSONB,
                osv_raw JSONB,
                cveorg_raw JSONB,
                cvss_score DOUBLE PRECISION,
                cvss_source TEXT,
                first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                sent_default_at TIMESTAMPTZ,
                sent_experimental_at TIMESTAMPTZ
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS subscribers (
                chat_id BIGINT PRIMARY KEY,
                modes TEXT[] NOT NULL DEFAULT '{}',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS bot_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_update_id BIGINT
            )
            """
        )
    conn.commit()


def get_cve_status(conn: psycopg.Connection, cve_id: str) -> tuple | None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT cve_id, sent_default_at, sent_experimental_at FROM cves WHERE cve_id = %s",
            (cve_id,),
        )
        return cur.fetchone()


def upsert_cve(
    conn: psycopg.Connection,
    cve_id: str,
    title: str,
    link: str,
    description: str,
    published_at,
    rss_raw: dict,
    circl_raw: dict | None,
    nvd_raw: dict | None,
    osv_raw: dict | None,
    cveorg_raw: dict | None,
    cvss_score: float | None,
    cvss_source: str,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cves (
                cve_id, title, link, description, published_at,
                rss_raw, circl_raw, nvd_raw, osv_raw, cveorg_raw,
                cvss_score, cvss_source, first_seen_at, last_seen_at
            )
            VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, NOW(), NOW()
            )
            ON CONFLICT (cve_id) DO UPDATE SET
                title = EXCLUDED.title,
                link = EXCLUDED.link,
                description = EXCLUDED.description,
                published_at = EXCLUDED.published_at,
                rss_raw = EXCLUDED.rss_raw,
                circl_raw = EXCLUDED.circl_raw,
                nvd_raw = EXCLUDED.nvd_raw,
                osv_raw = EXCLUDED.osv_raw,
                cveorg_raw = EXCLUDED.cveorg_raw,
                cvss_score = EXCLUDED.cvss_score,
                cvss_source = EXCLUDED.cvss_source,
                last_seen_at = NOW()
            """,
            (
                cve_id,
                title,
                link,
                description,
                published_at,
                Json(rss_raw),
                Json(circl_raw) if circl_raw is not None else None,
                Json(nvd_raw) if nvd_raw is not None else None,
                Json(osv_raw) if osv_raw is not None else None,
                Json(cveorg_raw) if cveorg_raw is not None else None,
                cvss_score,
                cvss_source,
            ),
        )
    conn.commit()


def mark_sent(conn: psycopg.Connection, cve_id: str, mode: str) -> None:
    column = "sent_default_at" if mode == "default" else "sent_experimental_at"
    with conn.cursor() as cur:
        cur.execute(
            f"UPDATE cves SET {column} = %s WHERE cve_id = %s",
            (datetime.now(timezone.utc), cve_id),
        )
    conn.commit()


def list_subscribers(conn: psycopg.Connection, mode: str) -> list[int]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT chat_id FROM subscribers WHERE %s = ANY(modes)",
            (mode,),
        )
        rows = cur.fetchall()
    return [row[0] for row in rows]


def add_subscription(conn: psycopg.Connection, chat_id: int, mode: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO subscribers (chat_id, modes)
            VALUES (%s, %s)
            ON CONFLICT (chat_id) DO UPDATE SET
                modes = (
                    SELECT ARRAY(
                        SELECT DISTINCT UNNEST(subscribers.modes || EXCLUDED.modes)
                    )
                ),
                updated_at = NOW()
            """,
            (chat_id, [mode]),
        )
    conn.commit()


def remove_subscription(conn: psycopg.Connection, chat_id: int, mode: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE subscribers
            SET modes = array_remove(modes, %s),
                updated_at = NOW()
            WHERE chat_id = %s
            """,
            (mode, chat_id),
        )
        cur.execute(
            "DELETE FROM subscribers WHERE chat_id = %s AND array_length(modes, 1) IS NULL",
            (chat_id,),
        )
    conn.commit()


def get_last_update_id(conn: psycopg.Connection) -> int | None:
    with conn.cursor() as cur:
        cur.execute("SELECT last_update_id FROM bot_state WHERE id = 1")
        row = cur.fetchone()
        return row[0] if row else None


def set_last_update_id(conn: psycopg.Connection, update_id: int | None) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO bot_state (id, last_update_id)
            VALUES (1, %s)
            ON CONFLICT (id) DO UPDATE SET last_update_id = EXCLUDED.last_update_id
            """,
            (update_id,),
        )
    conn.commit()


def migrate_subscribers_from_file(conn: psycopg.Connection) -> int:
    if not SUBSCRIBERS_FILE:
        return 0
    try:
        with open(SUBSCRIBERS_FILE, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError):
        return 0
    if not isinstance(payload, dict):
        return 0
    subscribers = payload.get("subscribers", [])
    if not isinstance(subscribers, list) or not subscribers:
        return 0
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM subscribers")
        count = cur.fetchone()[0]
        if count and count > 0:
            return 0
    migrated = 0
    for chat_id in subscribers:
        try:
            add_subscription(conn, int(chat_id), "default")
            migrated += 1
        except (TypeError, ValueError):
            continue
    return migrated
