from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=8, max_length=128)


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    email: str
    is_active: bool


class TokenResponse(BaseModel):
    access_token: str | None = None
    token_type: str = "bearer"
    expires_in: int | None = None
    user: UserResponse | None = None
    mfa_required: bool = False
    mfa_challenge: str | None = None


class MfaEnrollmentResponse(BaseModel):
    provisioning_uri: str
    manual_key: str


class MfaCodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=32)


class MfaStatusResponse(BaseModel):
    enabled: bool
    recovery_codes: list[str] | None = None

class MfaLoginRequest(BaseModel):
    challenge: str = Field(min_length=16, max_length=4096)
    code: str = Field(min_length=6, max_length=32)


class SessionResponse(BaseModel):
    id: UUID
    created_at: str
    last_activity_at: str
    expires_at: str
    user_agent: str | None
    current: bool


class MfaDisableRequest(MfaCodeRequest):
    use_recovery_code: bool = False


class AuthenticatorPasswordResetRequest(BaseModel):
    email: str = Field(min_length=5, max_length=255)
    code: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)
    confirm_password: str = Field(min_length=8, max_length=128)

    @model_validator(mode="after")
    def passwords_match(self):
        if self.new_password != self.confirm_password:
            raise ValueError("Passwords do not match.")
        return self
