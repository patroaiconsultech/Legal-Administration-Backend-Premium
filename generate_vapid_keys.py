"""Generate one stable VAPID keypair for Railway secrets.

Outputs URL-safe base64 without padding:
- VAPID_PRIVATE_KEY: raw P-256 private scalar (32 bytes)
- VAPID_PUBLIC_KEY: uncompressed P-256 public point (65 bytes)

Generate ONCE and persist the values as secrets. Rotating them invalidates
existing browser PushSubscriptions.
"""
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

key = ec.generate_private_key(ec.SECP256R1())
private_number = key.private_numbers().private_value.to_bytes(32, "big")
public_point = key.public_key().public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint,
)
print("VAPID_PRIVATE_KEY=" + b64url(private_number))
print("VAPID_PUBLIC_KEY=" + b64url(public_point))
print("VAPID_SUBJECT=mailto:contato@patroai.com")
