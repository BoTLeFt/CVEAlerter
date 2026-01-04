import json

from config import SUBSCRIBERS_FILE
from telegram_client import get_updates, send_message


def load_subscribers_state() -> dict:
    try:
        with open(SUBSCRIBERS_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"subscribers": [], "last_update_id": None}
    if not isinstance(data, dict):
        return {"subscribers": [], "last_update_id": None}
    data.setdefault("subscribers", [])
    data.setdefault("last_update_id", None)
    return data


def save_subscribers_state(state: dict) -> None:
    with open(SUBSCRIBERS_FILE, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2)


def update_subscribers(token: str, state: dict, timeout: int = 0) -> dict:
    offset = state.get("last_update_id")
    if offset is not None:
        offset = int(offset) + 1
    updates = get_updates(token, offset=offset, timeout=timeout)
    subscribers = set(state.get("subscribers", []))
    last_update_id = state.get("last_update_id")
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
            subscribers.add(chat_id)
            send_message(
                token,
                chat_id,
                "Subscribed. You'll receive critical CVEs once per day.",
            )
        elif text == "/unsubscribe":
            if chat_id in subscribers:
                subscribers.remove(chat_id)
            send_message(
                token,
                chat_id,
                "Unsubscribed. You will no longer receive updates.",
            )
    state["subscribers"] = sorted(subscribers)
    state["last_update_id"] = last_update_id
    return state
