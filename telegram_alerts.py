import os
import requests

BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"].strip()
CHAT_ID = 6269215067  # your private chat id

class TelegramAlerter:
    def __init__(self, bot_token: str = BOT_TOKEN, chat_id: int = CHAT_ID):
        self.base = f"https://api.telegram.org/bot{bot_token}"
        self.chat_id = chat_id

    def send(self, text: str, silent: bool = False):
        r = requests.post(
            f"{self.base}/sendMessage",
            json={
                "chat_id": self.chat_id,
                "text": text,
                "disable_notification": silent,
            },
            timeout=20,
        )
        r.raise_for_status()
        data = r.json()
        if not data.get("ok"):
            raise RuntimeError(data)
        return data["result"]

if __name__ == "__main__":
    TelegramAlerter().send("✅ Telegram alerts are working!")
