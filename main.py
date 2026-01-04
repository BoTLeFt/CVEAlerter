import argparse
import os
import sys
import time

from config import (
    CRITICAL_THRESHOLD,
    RECENT_WINDOW,
    RECENT_WINDOW_HOURS,
    RSS_URL,
    TELEGRAM_MAX_LEN,
)
from cve_feed import filter_critical_by_cvss, filter_recent, fetch_rss, parse_items
from message_format import build_header, render_messages, split_message
from subscriptions import load_subscribers_state, save_subscribers_state, update_subscribers
from telegram_client import send_message


def run_once(token: str | None) -> int:
    try:
        rss_xml = fetch_rss(RSS_URL)
        items = parse_items(rss_xml)
        recent_items = filter_recent(items, RECENT_WINDOW)
        circl_cache: dict = {}
        critical_items = filter_critical_by_cvss(
            recent_items, circl_cache, CRITICAL_THRESHOLD
        )
    except Exception as exc:
        print(f"Failed to fetch/parse RSS: {exc}", file=sys.stderr)
        return 1

    if not critical_items:
        print(f"No critical CVEs found in the last {RECENT_WINDOW_HOURS} hours.")
        return 0

    messages = render_messages(critical_items, circl_cache)
    header = build_header(len(critical_items))
    print(header)
    print("\n\n".join(messages))

    if not token:
        print("TOKEN env var is not set; skipping Telegram send.", file=sys.stderr)
        return 0

    state = load_subscribers_state()
    state = update_subscribers(token, state, timeout=0)
    save_subscribers_state(state)

    subscribers = state.get("subscribers", [])
    if not subscribers:
        print("No subscribers found. Users can send /subscribe to the bot.")
        return 0

    for chat_id in subscribers:
        send_message(token, chat_id, header)
        for message in messages:
            for chunk in split_message(message, TELEGRAM_MAX_LEN):
                send_message(token, chat_id, chunk)
    return 0


def run_bot(token: str | None) -> int:
    if not token:
        print("TOKEN env var is not set; bot mode requires a token.", file=sys.stderr)
        return 1

    state = load_subscribers_state()
    print("Bot mode started. Listening for /subscribe and /unsubscribe commands.")
    while True:
        try:
            state = update_subscribers(token, state, timeout=20)
            save_subscribers_state(state)
        except Exception as exc:
            print(f"Bot loop error: {exc}", file=sys.stderr)
            time.sleep(5)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CVE RSS -> Telegram notifier")
    parser.add_argument(
        "--mode",
        choices=("run-once", "bot"),
        default="run-once",
        help="run-once sends the daily digest; bot keeps listening for commands",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    token = os.getenv("TOKEN")
    if args.mode == "bot":
        return run_bot(token)
    return run_once(token)


if __name__ == "__main__":
    raise SystemExit(main())
