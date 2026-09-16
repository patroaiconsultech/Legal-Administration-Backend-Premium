from pathlib import Path
from io import BytesIO
import boto3
from botocore.client import Config
from .config import get_settings

settings = get_settings()

class Storage:
    def put(self, key: str, data: bytes, content_type: str):
        raise NotImplementedError
    def get(self, key: str) -> tuple[bytes, str]:
        raise NotImplementedError
    def exists(self, key: str) -> bool:
        raise NotImplementedError

class LocalStorage(Storage):
    def __init__(self):
        self.root = Path(settings.local_storage_dir)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, key, data, content_type):
        path = self.root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        (path.with_suffix(path.suffix + ".content_type")).write_text(content_type, encoding="utf-8")

    def get(self, key):
        path = self.root / key
        ct_path = path.with_suffix(path.suffix + ".content_type")
        content_type = ct_path.read_text(encoding="utf-8") if ct_path.exists() else "application/octet-stream"
        return path.read_bytes(), content_type

    def exists(self, key):
        return (self.root / key).exists()

class S3Storage(Storage):
    def __init__(self):
        kwargs = dict(
            service_name="s3",
            region_name=settings.s3_region,
            aws_access_key_id=settings.s3_access_key_id,
            aws_secret_access_key=settings.s3_secret_access_key,
            config=Config(signature_version="s3v4"),
        )
        if settings.s3_endpoint_url:
            kwargs["endpoint_url"] = settings.s3_endpoint_url
        self.client = boto3.client(**kwargs)
        self.bucket = settings.s3_bucket

    def put(self, key, data, content_type):
        extra = {"ContentType": content_type}
        if settings.s3_kms_key_id:
            extra.update(ServerSideEncryption="aws:kms", SSEKMSKeyId=settings.s3_kms_key_id)
        else:
            extra.update(ServerSideEncryption="AES256")
        self.client.put_object(Bucket=self.bucket, Key=key, Body=data, **extra)

    def get(self, key):
        obj = self.client.get_object(Bucket=self.bucket, Key=key)
        return obj["Body"].read(), obj.get("ContentType") or "application/octet-stream"

    def exists(self, key):
        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
            return True
        except Exception:
            return False

def get_storage() -> Storage:
    return S3Storage() if settings.storage_mode == "s3" else LocalStorage()
