import json
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def telegram_api_request(token: str, method: str, payload: dict, timeout: int = 15) -> dict:
    url = f"https://api.telegram.org/bot{token}/{method}"
    data = urlencode(payload).encode("utf-8")
    req = Request(url, data=data, method="POST")
    try:
        with urlopen(req, timeout=timeout) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Telegram API error {exc.code}: {error_body}") from exc
    try:
        payload = json.loads(resp_body)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Telegram API returned invalid JSON.") from exc
    if not payload.get("ok", False):
        raise RuntimeError(f"Telegram API responded with ok=false: {resp_body}")
    return payload


def send_message(token: str, chat_id: str, text: str, parse_mode: str = "HTML") -> None:
    telegram_api_request(
        token,
        "sendMessage",
        {"chat_id": chat_id, "text": text, "parse_mode": parse_mode},
    )


def get_updates(token: str, offset: int | None, timeout: int = 0) -> list:
    payload: dict = {"timeout": timeout}
    if offset is not None:
        payload["offset"] = offset
    response = telegram_api_request(token, "getUpdates", payload, timeout=timeout + 5)
    return response.get("result", [])
