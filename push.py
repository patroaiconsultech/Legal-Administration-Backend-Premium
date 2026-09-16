import json
from sqlalchemy import select
from sqlalchemy.orm import Session
from .config import get_settings
from .models import PushSubscription, utcnow

settings = get_settings()

def push_available() -> bool:
    return bool(settings.push_enabled and settings.vapid_public_key and settings.vapid_private_key and settings.vapid_subject)

def send_admin_push(db: Session, *, title: str, body: str, url: str) -> dict:
    if not push_available():
        return {"enabled": False, "attempted": 0, "delivered": 0, "revoked": 0}

    from pywebpush import webpush, WebPushException

    subscriptions = db.scalars(
        select(PushSubscription).where(PushSubscription.revoked_at.is_(None))
    ).all()
    payload = json.dumps({"title": title, "body": body, "url": url}, ensure_ascii=False)
    result = {"enabled": True, "attempted": 0, "delivered": 0, "revoked": 0}

    for sub in subscriptions:
        result["attempted"] += 1
        try:
            webpush(
                subscription_info={
                    "endpoint": sub.endpoint,
                    "keys": {"p256dh": sub.p256dh, "auth": sub.auth},
                },
                data=payload,
                vapid_private_key=settings.vapid_private_key,
                vapid_claims={"sub": settings.vapid_subject},
                ttl=300,
            )
            sub.last_used_at = utcnow()
            sub.failure_count = 0
            result["delivered"] += 1
        except WebPushException as exc:
            sub.failure_count = int(sub.failure_count or 0) + 1
            status = getattr(getattr(exc, "response", None), "status_code", None)
            if status in {404, 410}:
                sub.revoked_at = utcnow()
                result["revoked"] += 1
        except Exception:
            sub.failure_count = int(sub.failure_count or 0) + 1
    db.flush()
    return result
