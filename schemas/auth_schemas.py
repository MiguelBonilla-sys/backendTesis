"""Pydantic v2 request/response schemas for authentication endpoints."""

from pydantic import BaseModel, Field, field_validator, model_validator

ALLOWED_DOMAINS: tuple[str, ...] = (
    "@academia.usbbog.edu.co",
    "@usbbog.edu.co",
)


def _normalize_email(value: str) -> str:
    lowered = value.strip().lower()
    if "@" not in lowered:
        raise ValueError("Invalid email format")
    local, domain = lowered.split("@", 1)
    if not local or not domain or "." not in domain:
        raise ValueError("Invalid email format")
    return lowered


class LoginRequest(BaseModel):
    email: str
    password: str = Field(min_length=8)

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return _normalize_email(v)


class RegisterRequest(BaseModel):
    email: str
    password: str = Field(min_length=8, max_length=72)  # bcrypt 72-char limit
    confirm_password: str

    @field_validator("email")
    @classmethod
    def must_be_university_domain(cls, v: str) -> str:
        lower = _normalize_email(v)
        if not any(lower.endswith(d) for d in ALLOWED_DOMAINS):
            raise ValueError(
                "Email must be a USB institutional address "
                "(@academia.usbbog.edu.co or @usbbog.edu.co)"
            )
        return lower

    @model_validator(mode="after")
    def passwords_match(self) -> "RegisterRequest":
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match")
        return self


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds (= ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    role: str  # "admin" | "student"
