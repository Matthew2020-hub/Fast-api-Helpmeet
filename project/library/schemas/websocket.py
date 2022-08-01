from pydantic import BaseModel, Field


class MessageCreate(BaseModel):
    message: str = Field(...)



class UserPublic(BaseModel):
    full_name: str
    is_admin: bool



class MessagePublic(BaseModel):
    room_id: str
    author: UserPublic
    short_id: str
    created_at: str


def message_schema(data) -> dict:
    return {
        "room_id": data.room.room_id,
        "author": data.author,
        "message": data.content,
        "timestamp": (data.created_at).strftime("%a. %I:%M %p"),
        "short_id": data.short_id,
    }