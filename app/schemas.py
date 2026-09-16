from pydantic import BaseModel, EmailStr, Field

class IdentifyRequest(BaseModel):
    token: str
    name: str = Field(min_length=2, max_length=255)
    email: EmailStr
    organization: str = Field(min_length=2, max_length=255)
    role: str = Field(min_length=2, max_length=255)

class OTPVerifyRequest(BaseModel):
    token: str
    code: str = Field(pattern=r"^\d{6}$")

class AcceptRequest(BaseModel):
    timezone: str = Field(min_length=1, max_length=100)
    representation_mode: str
    representation_declaration: str | None = None
    accepted: bool

class AgentChatRequest(BaseModel):
    question: str = Field(min_length=2, max_length=4000)
    thread_id: str | None = None

class AdminStartRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=200)

class AdminVerifyRequest(BaseModel):
    email: EmailStr
    code: str = Field(pattern=r"^\d{6}$")

class CreateInvitationRequest(BaseModel):
    email: EmailStr
    name: str | None = None
    organization: str = "Estevez Guarda Administração Judicial Ltda."
    role: str | None = None
    days_valid: int = Field(default=7, ge=1, le=30)


class AccessRequestCreate(BaseModel):
    full_name: str = Field(min_length=2, max_length=255)
    email: EmailStr
    organization: str = Field(min_length=2, max_length=255)
    role: str = Field(min_length=2, max_length=255)
    purpose: str = Field(min_length=5, max_length=2000)

class AccessConsumeRequest(BaseModel):
    token: str = Field(min_length=32, max_length=500)

class AdminAccessDecision(BaseModel):
    reason: str = Field(min_length=2, max_length=1000)

class PushSubscriptionCreate(BaseModel):
    endpoint: str = Field(min_length=20, max_length=4096)
    p256dh: str = Field(min_length=20, max_length=4096)
    auth: str = Field(min_length=8, max_length=4096)
