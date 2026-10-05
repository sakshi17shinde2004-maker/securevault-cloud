"""Storage abstraction: same API for local folder and Amazon S3."""
from functools import lru_cache
from pathlib import Path

from .config import settings


class LocalStorage:
    def __init__(self, base: Path):
        self.base = base.resolve()
        self.base.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        p = (self.base / key).resolve()
        if self.base not in p.parents:
            raise ValueError("Invalid storage key")
        return p

    def save(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        p = self._path(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    def read(self, key: str) -> bytes:
        return self._path(key).read_bytes()

    def delete(self, key: str) -> None:
        self._path(key).unlink(missing_ok=True)


class S3Storage:
    def __init__(self, bucket: str, region: str):
        import boto3  # imported lazily: only needed in the AWS phase
        if not bucket:
            raise RuntimeError("S3_BUCKET is not configured")
        self.bucket = bucket
        self.client = boto3.client("s3", region_name=region)  # credentials come from IAM Role / env

    def save(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        self.client.put_object(Bucket=self.bucket, Key=key, Body=data,
                               ContentType=content_type, ServerSideEncryption="AES256")

    def read(self, key: str) -> bytes:
        return self.client.get_object(Bucket=self.bucket, Key=key)["Body"].read()

    def delete(self, key: str) -> None:
        self.client.delete_object(Bucket=self.bucket, Key=key)


@lru_cache(maxsize=1)
def get_storage():
    if settings.STORAGE_BACKEND == "s3":
        return S3Storage(settings.S3_BUCKET, settings.AWS_REGION)
    return LocalStorage(settings.UPLOAD_DIR)
