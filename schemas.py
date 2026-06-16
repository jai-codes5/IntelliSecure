from pydantic import BaseModel, Field

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None
    role: str | None = None

class UserCreate(BaseModel):
    username: str
    password: str
    role: str = Field(default="Employee", description="Admin, Manager, or Employee")

class UserOut(BaseModel):
    id: int
    username: str
    role: str

    class Config:
        from_attributes = True