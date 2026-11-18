from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


DEFAULT_DATABASE_URL = "postgresql://collector_user:CHANGE_ME@localhost:5432/skill_collector"
DEFAULT_S3_BUCKET = "openclaw-skill-artifacts"
DEFAULT_AWS_REGION = "us-east-1"
DEFAULT_ARTIFACT_TMP_DIR = "/tmp/openclaw-analysis"


@dataclass(frozen=True)
class Settings:
    database_url: str
    s3_bucket: str
    aws_region: str
    artifact_tmp_dir: Path

    @property
    def sqlalchemy_database_url(self) -> str:
        return normalize_postgres_driver(self.database_url)


def normalize_postgres_driver(database_url: str) -> str:
    if database_url.startswith("postgresql://"):
        return "postgresql+psycopg://" + database_url.removeprefix("postgresql://")
    if database_url.startswith("postgres://"):
        return "postgresql+psycopg://" + database_url.removeprefix("postgres://")
    return database_url


def get_settings(env_file: str | Path | None = ".env") -> Settings:
    if env_file:
        load_dotenv(env_file)

    return Settings(
        database_url=os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL),
        s3_bucket=os.getenv("S3_BUCKET", DEFAULT_S3_BUCKET),
        aws_region=os.getenv("AWS_REGION", DEFAULT_AWS_REGION),
        artifact_tmp_dir=Path(os.getenv("ARTIFACT_TMP_DIR", DEFAULT_ARTIFACT_TMP_DIR)),
    )
