from tortoise import fields
from models.base import BaseModel
from library.dependencies.utils import generate_short_id

class User(BaseModel):

    email = fields.CharField(max_length=100, null=True)
    full_name = fields.CharField(max_length=20, blank=True, null=True)
    hashed_password = fields.CharField(max_length=100, blank=True, null=True)
    house_address = fields.CharField(max_length=200, null=True)
    estate_name = fields.CharField(max_length=20, blank=True, null=True)
    profile_image = fields.CharField(max_length=250, blank=True, null=True)
    is_admin = fields.BooleanField(default=False)
    is_verify = fields.BooleanField(default=False)


class Estate(BaseModel):
    member = fields.ForeignKeyField(
        "models.User",on_delete="CASCADE", null=True
        )
    estate_name = fields.CharField(
        max_length=200, 
        null=True, blank=False, 
        )
    estate_profile_image = fields.CharField(
        max_length=250, 
        null=True
        )
    estate_address = fields.CharField(
        max_length=400, 
        blank=False
        )
    estate_country = fields.CharField(
        max_length=15, 
        blank=False
        )
    public_id = fields.CharField(
        max_length=15, 
        default=generate_short_id, 
        unique=True
        )
        