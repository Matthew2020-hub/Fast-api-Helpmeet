import random
from tortoise import fields
from project.models.base import BaseModel
from project.library.dependencies.utils import generate_short_id
from project.models.user import User

class Room(BaseModel):
    estate = fields.OneToOneField("models.Estate", on_delete='CASCADE')
    room_id = fields.CharField(
        max_length=255, default=generate_short_id(), unique=True
        )


class Message(BaseModel):
    room = fields.ForeignKeyField(
        Room, related_name="messages", on_delete='CASCADE', null=True
    )
    author = fields.ForeignKeyField(
        User, related_name="author", on_delete='CASCADE', null=True
    )
    content = fields.TextField(unique=False, blank=False)
    short_id = fields.CharField(
        max_length=255, default=generate_short_id(), unique=True
    )
