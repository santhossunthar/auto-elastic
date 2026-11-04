from functools import lru_cache
import warnings

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

import urllib3
from elastic_transport import SecurityWarning
from urllib3.exceptions import InsecureRequestWarning


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ESA_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    elasticsearch_url: str = "https://localhost:9200"
    elasticsearch_api_key: SecretStr | None = None
    kibana_url: str | None = None
    verify_certs: bool = True
    suppress_insecure_request_warnings: bool = False
    request_timeout: float = 30.0

    @field_validator("elasticsearch_url", "kibana_url")
    @classmethod
    def validate_http_url(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        normalized = value.rstrip("/")
        if not normalized.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return normalized

    @field_validator("request_timeout")
    @classmethod
    def validate_timeout(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("request timeout must be greater than zero")
        return value

    def require_api_key(self) -> str:
        if self.elasticsearch_api_key is None:
            raise ValueError(
                "Elasticsearch API key is required; set ESA_ELASTICSEARCH_API_KEY in .env"
            )
        return self.elasticsearch_api_key.get_secret_value()

    def require_kibana_url(self) -> str:
        if self.kibana_url is None:
            raise ValueError(
                "Kibana URL is required; set ESA_KIBANA_URL in .env to use data-view commands"
            )
        return self.kibana_url

    def configure_tls_warnings(self) -> None:
        if self.suppress_insecure_request_warnings:
            urllib3.disable_warnings(InsecureRequestWarning)
            warnings.filterwarnings("ignore", category=SecurityWarning)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
