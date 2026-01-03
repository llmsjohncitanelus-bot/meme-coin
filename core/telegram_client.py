import requests


class TelegramClient:
    def __init__(self, bot_token: str, chat_id: int):
        self.bot_token = bot_token.strip()
        self.chat_id = int(chat_id)
        self.base = f"https://api.telegram.org/bot{self.bot_token}"
        self.session = requests.Session()

    def send(self, text: str, silent: bool = False) -> None:
        r = self.session.post(
            f"{self.base}/sendMessage",
            json={
                "chat_id": self.chat_id,
                "text": text,
                "disable_notification": bool(silent),
                "disable_web_page_preview": True,
            },
            timeout=20,
        )
        r.raise_for_status()
        data = r.json()
        if not data.get("ok"):
            raise RuntimeError(data)
