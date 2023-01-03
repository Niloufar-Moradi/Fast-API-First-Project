from sqlalchemy.orm import Session
from fastapi import HTTPException
from . import models, schemas
from typing import Union, Dict, Any, List
import bcrypt
from fastapi.encoders import jsonable_encoder
from datetime import datetime
from .security import get_password_hash, verify_password




############## USER ###################

    #### Crud For Users #####





def get_user(db: Session, 
             user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()


def get_user_by_email(db: Session, email: str) -> Union[models.User, None]:
    return db.query(models.User).filter(models.User.email == email).first()

            #### NEED SOME ACTIONS 
def get_users(db: Session, 
              skip: int = 0, 
              limit: int = 100):
    return db.query(models.User).offset(skip).limit(limit=limit).all()



def create_user(db: Session, user: schemas.CreateUser) -> models.User:
    
    db_user = models.User(
        email= user.email,
        hashed_password = get_password_hash(user.password),

    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return db_user

def update_user(
    db: Session, 
    db_user: models.User, 
    user: Union[schemas.UpdateUser, 
    Dict[str, Any]]
    ) -> models.User:
    
    # print("user is:", user)
    # print("db_user is: ", db_user)
    # print("user.dict(exclude_unset=True): ", user.dict(exclude_unset=True))

    db_data = jsonable_encoder(db_user)
    # print("db_data is: ", db_data)
    if isinstance (user, dict):
        update_data = user
    else:
        update_data = user.dict(exclude_unset=False)
    # print("update data: ", update_data)
    if update_data["password"]:
        hashed_password = get_password_hash(update_data["password"])
        del update_data["password"]
        update_data["hashed_password"] = hashed_password

    for field in db_data:
        if field in update_data:

            setattr(db_user, field, update_data[field])

    # my_user = db.get(models.User, user_id)
    # update_data = user.dict

    db.add(db_user)    
    db.commit()
    db.refresh(db_user)
    return db_user     
    
def delete_user(
    db: Session,
    user_id: int
):

    user = db.query(models.User).filter(models.User.id==user_id).first()
    db.delete(user)
    db.commit()

    return True
    # db.query(models.User).filter(models.User.id == user_id).delete()
    # db.commit()

    



"""
Authentication
"""
def user_authentication(
            db: Session,
            email: str,
            password: str

        )-> Union[models.User, None]:
    user = get_user_by_email(db=db, email=email)
    if not user:
        return None
    if not verify_password(plain_password=password, hashed_password=user.hashed_password):
        return None
    return user




def is_active(user: models.User) -> bool:
    return user.is_active


def is_admin(user: models.User) -> bool:
    return user.is_admin
################# Items #######################

def get_items (
        db: Session, 
        skip: int = 0, 
        limit: int = 100
        ) -> list[models.Item]:
    return db.query(models.Item).offset(skip).limit(limit=limit).all()


def get_items_of_the_user (
            db: Session, 
            owner_id:int, 
            skip: int = 0, limit: int = 100
            )-> List[models.Item]:


    return db.query(models.Item).\
                filter(models.Item.owner_id == owner_id).\
                offset(skip).limit(limit=limit).all()

def get_item(db: Session, item_id: int):
    return db.query(models.Item).filter(models.Item.id == item_id).first()


def create_user_item(
            db: Session, 
            # item: schemas.ItemCreate, 
            item: schemas.ItemBase, 
            owner_id: int
            )-> models.Item:

    print("item request is:", item, owner_id)

    # db_item = db.query(models.Item).filter(models.Item.title == item.title).first()

    # # print(jsonable_encoder(db_item))

    # # if db_item:
    # #     print(db_item.title, db_item.description, db_item.owner_id)

    # if (db_item.title, db_item.description, db_item.owner_id) == (item.title, item.description, owner_id):
    #     return False
    
        # print("YEEEEEEEEEEEES")
    item_data = jsonable_encoder(item)
    print("item data jsonable reader: ", item_data)
    db_item = models.Item(**item_data, owner_id=owner_id, created_at=datetime.now())
    # print("db item: ", )

    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item



def read_item_by_title(
            db: Session, 
            item_title: str,
            # user_id: int 
            # owner_id: int
            ):

    # item = get_item(db=db, item_id=item_id)
    item = db.query(models.Item).filter(models.Item.title == item_title).first()
    print(item)
    

    # item_data = jsonable_encoder(item)
    # db_item = models.Item(**item_data, owner_id=owner_id)

    # db.add(db_item)
    # db.commit()
    # db.refresh(db_item)
    return item




def update_item(
            db: Session, 
            db_item: models.Item, 
            item: Union[schemas.ItemUpdate, Dict[str, Any]],
            # updated_at: datetime,
            ) -> models.Item:
            
    db_data = jsonable_encoder(db_item)
    if isinstance (item, dict):
        update_data = item
    else:
        update_data = item.dict(exclude_unset=True)

    for field in db_data:
        if field in update_data:

            setattr(db_item, field, update_data[field])

    print("db_item", db_item)

    db.add(db_item)    
    db.commit()
    db.refresh(db_item)
    return db_item     

def delete_item(item_id: int, db: Session):
    db.query(models.Item).filter(models.Item.id == item_id).delete()
    db.commit()

    return True