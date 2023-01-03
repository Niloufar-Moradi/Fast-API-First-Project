from typing import Union
from pydantic import BaseModel
from datetime import datetime

################# USER ####################

#### Shared Properties
class UserBase(BaseModel):
    email: Union[str, None] = None
    is_active: Union[bool, None] = True


class CreateUser(UserBase):
    password: str


class UpdateUser(UserBase):
    email: Union[str, None] = None
    password: Union[str, None] = None
    


### Properties shared by model in database
class UserInDBBase(UserBase):
    id: Union[int, None] = None

    class Config:
        orm_mode = True


### Properties to resturn to client
class User(UserInDBBase):
    pass

### Properties stored in DB

class UserInDB(UserInDBBase):
    hashed_password: str


################## Item ##############

class ItemBase(BaseModel):
    title: Union[str, None] = None
    description: Union[str, None] = None
    # updated_time: Union[datetime, None]
    # created_at: datetime


# class ItemCreate(ItemBase):
class ItemCreate(BaseModel):
    # updated_time: Union[datetime, None]
    title: str
    description: Union[str, None] = None

class ItemUpdate(ItemBase):
    
    pass


    ### Properties shared by model in database
class ItemInDBBase(ItemBase):
    id: int
    title: str
    owner_id: int

    class Config:
        orm_mode = True

    ### Properties to return to client
class Item(ItemInDBBase):
    pass

    ### Properties stored in DB
class ItemInDB(ItemInDBBase):
    pass



############# TOKEN #################

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenPayload(BaseModel):
    sub: Union[int, None] = None