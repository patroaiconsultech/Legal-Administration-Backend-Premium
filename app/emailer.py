import httpx
from .config import get_settings

settings = get_settings()

async def send_email(to: str, subject: str, html: str):
    if not settings.resend_api_key:
        if settings.environment == "production":
            raise RuntimeError("RESEND_API_KEY ausente")
        print(f"[DEV EMAIL] to={to} subject={subject}")
        print(html)
        return {"id": "dev-no-send"}

    payload = {
        "from": settings.resend_from,
        "to": [to],
        "subject": subject,
        "html": html,
        "reply_to": settings.resend_reply_to,
    }
    headers = {"Authorization": f"Bearer {settings.resend_api_key}", "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post("https://api.resend.com/emails", json=payload, headers=headers)
        r.raise_for_status()
        return r.json()
