import random
import re
regex = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*+=]).{8,}$"


def to_lower_case(data: str):
    return data.lower()


def generate_short_id(size=10, chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"):
    return "".join(random.choice(chars) for _ in range(size))

def validate_password(values):
    """Validate password matches a given regex patter
        Raise:
            Valuerror if password doesn't match the regex pattern
    """
    password = values.get("password")
    if not re.match(regex, password):
        raise ValueError(
            "Password must contain Min. 8 characters, 1 Uppercase,\
            1 lowercase, 1 number, and 1 special character"
        )
    return values

