from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_env: str = "production"
    secret_key: str
    database_url: str
    session_cookie_name: str = "messis_session"
    session_max_age_seconds: int = 28800
    login_max_attempts: int = 5
    login_lock_minutes: int = 15
    signup_access_code: str = ""
    signup_max_attempts: int = 5
    signup_window_seconds: int = 900
    passcode_reset_minutes: int = 30
    passcode_reset_max_attempts: int = 5
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from_email: str = ""
    smtp_use_tls: bool = True
    smtp_use_ssl: bool = False
    public_base_url: str = ""
    csrf_trusted_origins: str = ""
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

@lru_cache
def get_settings() -> Settings:
    return Settings()
