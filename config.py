from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "development"
    app_name: str = "Efatá Secure Briefing Portal"
    public_base_url: str = "http://localhost:5173"
    frontend_origin: str = "http://localhost:5173"
    database_url: str = "sqlite:///./efata_secure.db"

    secret_key: str = "CHANGE_ME_IN_PRODUCTION"
    cookie_secure: bool = False
    access_session_hours: int = 8
    invitation_days: int = 7
    otp_minutes: int = 10
    otp_max_attempts: int = 5

    resend_api_key: str | None = None
    resend_from: str = "PatroAI <contato@patroai.com>"
    resend_reply_to: str = "contato@patroai.com"
    privacy_email: str = "contato@patroai.com"

    storage_mode: str = "local"
    local_storage_dir: str = "./private_storage"
    s3_bucket: str | None = None
    s3_region: str | None = None
    s3_endpoint_url: str | None = None
    s3_access_key_id: str | None = None
    s3_secret_access_key: str | None = None
    s3_kms_key_id: str | None = None

    admin_email: str = "contato@patroai.com"
    admin_password_hash: str | None = None

    # Canonical admission mode for this portal.
    # "superadmin" disables all visitor OTP endpoints; admin OTP remains separate.
    access_approval_mode: str = "superadmin"
    access_request_enabled: bool = True
    access_request_window_minutes: int = 30
    access_request_max_per_window: int = 5
    approval_link_hours: int = 72

    push_enabled: bool = False
    vapid_public_key: str | None = None
    vapid_private_key: str | None = None
    vapid_subject: str = "mailto:contato@patroai.com"

    agent_enabled: bool = False
    agent_provider: str = "openai"
    agent_model: str = "gpt-5.6-luna"
    openai_api_key: str | None = None
    agent_store_content: bool = False
    agent_max_output_chars: int = 5000

    seed_content_on_startup: bool = True

    def validate_production(self) -> None:
        if self.environment.lower() != "production":
            return
        errors = []
        if self.secret_key == "CHANGE_ME_IN_PRODUCTION" or len(self.secret_key) < 32:
            errors.append("SECRET_KEY forte é obrigatório")
        if not self.cookie_secure:
            errors.append("COOKIE_SECURE=true é obrigatório")
        if not self.database_url.startswith(("postgresql://", "postgresql+psycopg://")):
            errors.append("PostgreSQL é obrigatório")
        if self.storage_mode != "s3":
            errors.append("STORAGE_MODE=s3 é obrigatório")
        if not all([self.s3_bucket, self.s3_region, self.s3_access_key_id, self.s3_secret_access_key]):
            errors.append("configuração S3 incompleta")
        if not self.resend_api_key:
            errors.append("RESEND_API_KEY é obrigatório")
        if not self.admin_password_hash:
            errors.append("ADMIN_PASSWORD_HASH é obrigatório")
        if self.access_approval_mode != "superadmin":
            errors.append("ACCESS_APPROVAL_MODE=superadmin é obrigatório nesta release")
        if self.push_enabled and not all([self.vapid_public_key, self.vapid_private_key, self.vapid_subject]):
            errors.append("VAPID_PUBLIC_KEY/VAPID_PRIVATE_KEY/VAPID_SUBJECT obrigatórios quando PUSH_ENABLED=true")
        if self.agent_enabled and self.agent_provider == "openai" and not self.openai_api_key:
            errors.append("OPENAI_API_KEY é obrigatório quando AGENT_ENABLED=true e AGENT_PROVIDER=openai")
        if errors:
            raise RuntimeError("Production fail-closed: " + "; ".join(errors))

@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.validate_production()
    return s
