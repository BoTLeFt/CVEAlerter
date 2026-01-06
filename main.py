import argparse
import os
import sys
import time

from config import CRITICAL_THRESHOLD, RECENT_WINDOW, RECENT_WINDOW_HOURS, RSS_URL, TELEGRAM_MAX_LEN
from cve_feed import (
    compute_cvss,
    extract_cve_id,
    fetch_rss,
    fetch_sources,
    filter_recent,
    parse_fields,
    parse_items,
    clean_html,
)
from db import (
    ensure_schema,
    get_conn,
    get_cve_status,
    list_subscribers,
    migrate_subscribers_from_file,
    mark_sent,
    upsert_cve,
)
from message_format import build_header, render_messages, split_message
from subscriptions import update_subscribers
from telegram_client import send_message


def build_rss_raw(item) -> dict:
    return {
        "title": item.title,
        "link": item.link,
        "description": item.description,
        "pubDate": item.published_at.isoformat() if item.published_at else None,
    }


def collect_records(conn, items, send_mode: str, send_only_new: bool) -> list[dict]:
    records = []
    for item in items:
        description_clean = clean_html(item.description) if item.description else ""
        rss_fields = parse_fields(description_clean)
        cve_id = rss_fields["cve_id"] or extract_cve_id(item.title)
        if not cve_id:
            continue

        status = get_cve_status(conn, cve_id)
        exists = status is not None
        sent_default_at = status[1] if status else None
        sent_experimental_at = status[2] if status else None

        sources = fetch_sources(cve_id)
        cvss_score, cvss_source = compute_cvss(sources, rss_fields)

        upsert_cve(
            conn=conn,
            cve_id=cve_id,
            title=item.title,
            link=item.link,
            description=rss_fields.get("description") or item.description,
            published_at=item.published_at,
            rss_raw=build_rss_raw(item),
            circl_raw=sources.get("circl"),
            nvd_raw=sources.get("nvd"),
            osv_raw=sources.get("osv"),
            cveorg_raw=sources.get("cveorg"),
            cvss_score=cvss_score,
            cvss_source=cvss_source,
        )

        if cvss_score is None or cvss_score <= CRITICAL_THRESHOLD:
            continue

        if send_mode == "default":
            if sent_default_at is not None:
                continue
            if send_only_new and exists:
                continue
        else:
            if sent_experimental_at is not None:
                continue
            if send_only_new and exists:
                continue

        records.append(
            {
                "cve_id": cve_id,
                "item": item,
                "sources": sources,
                "cvss_score": cvss_score,
            }
        )
    return records


def dispatch_records(conn, token: str, mode: str, records: list[dict]) -> None:
    if not records:
        print("No matching CVEs to send.")
        return

    subscribers = list_subscribers(conn, mode)
    if not subscribers:
        print(f"No subscribers found for mode: {mode}.")
        return

    header = build_header(len(records), mode)
    messages = render_messages(records)

    for chat_id in subscribers:
        send_message(token, chat_id, header)
        for message in messages:
            for chunk in split_message(message, TELEGRAM_MAX_LEN):
                send_message(token, chat_id, chunk)

    for record in records:
        mark_sent(conn, record["cve_id"], mode)


def run_ingest(token: str | None) -> int:
    with get_conn() as conn:
        ensure_schema(conn)
        migrate_subscribers_from_file(conn)
        rss_xml = fetch_rss(RSS_URL)
        items = parse_items(rss_xml)
        records = collect_records(conn, items, send_mode="experimental", send_only_new=True)

        if not token:
            print("TOKEN env var is not set; skipping Telegram send.", file=sys.stderr)
            return 0

        dispatch_records(conn, token, "experimental", records)
    return 0


def run_once(token: str | None) -> int:
    with get_conn() as conn:
        ensure_schema(conn)
        migrate_subscribers_from_file(conn)
        rss_xml = fetch_rss(RSS_URL)
        items = parse_items(rss_xml)
        recent_items = filter_recent(items, RECENT_WINDOW)
        records = collect_records(conn, recent_items, send_mode="default", send_only_new=False)

        if not token:
            print("TOKEN env var is not set; skipping Telegram send.", file=sys.stderr)
            return 0

        dispatch_records(conn, token, "default", records)
    return 0


def run_bot(token: str | None) -> int:
    if not token:
        print("TOKEN env var is not set; bot mode requires a token.", file=sys.stderr)
        return 1

    with get_conn() as conn:
        ensure_schema(conn)
        migrate_subscribers_from_file(conn)
        print("Bot mode started. Listening for commands.")
        while True:
            try:
                update_subscribers(token, conn, timeout=20)
            except Exception as exc:
                print(f"Bot loop error: {exc}", file=sys.stderr)
                time.sleep(5)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CVE RSS -> Telegram notifier")
    parser.add_argument(
        "--mode",
        choices=("run-once", "bot", "ingest"),
        default="run-once",
        help="run-once sends daily digest; bot listens for commands; ingest scans full feed",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    token = os.getenv("TOKEN")
    if args.mode == "bot":
        return run_bot(token)
    if args.mode == "ingest":
        return run_ingest(token)
    return run_once(token)


if __name__ == "__main__":
    raise SystemExit(main())
