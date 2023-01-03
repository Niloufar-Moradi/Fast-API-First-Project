from datetime import timedelta, datetime
from passlib.context import CryptContext
from typing import Any, Union
from jose import jwt

from secrets import token_bytes
from base64 import b64encode


SECRET_KEY = "1e6683e6b02c17cc0dcf19868e0abe59d9e901f907419e31f4717034c588195e"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALGORITHM = "HS256"


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str)-> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_acees_token(
    sub: Union[str, Any], 
    expires_delta: timedelta = None):
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=30)
    
    to_encode = {"exp": expire, "sub": str(sub)}
    encoded_jwt = jwt.encode(to_encode,  SECRET_KEY, algorithm=ALGORITHM)
    
    return encoded_jwt
