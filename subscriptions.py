from db import add_subscription, get_last_update_id, remove_subscription, set_last_update_id
from telegram_client import get_updates, send_message


def update_subscribers(token: str, conn, timeout: int = 0) -> None:
    offset = get_last_update_id(conn)
    if offset is not None:
        offset = int(offset) + 1
    updates = get_updates(token, offset=offset, timeout=timeout)
    last_update_id = get_last_update_id(conn)
    for update in updates:
        update_id = update.get("update_id")
        if update_id is not None:
            last_update_id = update_id
        message = update.get("message") or update.get("edited_message") or {}
        text = (message.get("text") or "").strip()
        chat = message.get("chat") or {}
        chat_id = chat.get("id")
        if chat_id is None:
            continue
        if text == "/subscribe":
            add_subscription(conn, chat_id, "default")
            send_message(
                token,
                chat_id,
                "Subscribed (default). You'll receive daily critical CVEs.",
            )
        elif text == "/unsubscribe":
            remove_subscription(conn, chat_id, "default")
            send_message(
                token,
                chat_id,
                "Unsubscribed from default updates.",
            )
        elif text == "/subscribe-experimental":
            add_subscription(conn, chat_id, "experimental")
            send_message(
                token,
                chat_id,
                "Subscribed (experimental). You'll receive new CVEs every 15 minutes.",
            )
        elif text == "/unsubscribe-experimental":
            remove_subscription(conn, chat_id, "experimental")
            send_message(
                token,
                chat_id,
                "Unsubscribed from experimental updates.",
            )
    set_last_update_id(conn, last_update_id)
