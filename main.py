
"""
that is a project
"""

from fastapi import FastAPI, Depends, HTTPException, Body, status, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import time

from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.concurrency import iterate_in_threadpool

from sqlalchemy.orm import Session

from datetime import timedelta
from datetime import datetime, timezone

from typing import Union

from pydantic import ValidationError

from . import models
from .database import SessionLocal, engine
from . import schemas, models, crud, security

from fastapi import logger

from jose import jwt

from fastapi.responses import UJSONResponse

from typing import Any

from fastapi.responses import FileResponse

from fastapi.responses import JSONResponse

################

models.Base.metadata.create_all(bind=engine)

# some_file_path = "test"

app = FastAPI(debug=True)

"""
logger config
"""
import logging
import time
import random
import string


class CustomFormatter(logging.Formatter):

    cian = "\x1b[0;36m"
    green = "\x1b[0;32m"
    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"

    FORMATS = {
        logging.DEBUG: green + format + reset,
        logging.INFO: cian + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
fh = logging.FileHandler(filename='./server.log')
# formatter = logging.Formatter(
#     "%(asctime)s - %(module)s - %(funcName)s - line:%(lineno)d - %(levelname)s - %(message)s"
# )
# formatter = logging.Formatter(CustomFormatter())


ch.setFormatter(CustomFormatter())
fh.setFormatter(CustomFormatter())

# ch.setFormatter(formatter)
# fh.setFormatter(formatter)
logger.addHandler(ch)  # Exporting logs to the screen
logger.addHandler(fh)  # Exporting logs to a file

logger = logging.getLogger(__name__)

######***************************

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login/access-token")
ACCESS_TOKEN_EXPIRE_MINUTES = 30


######## Dependencies #############

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
        db: Session = Depends(get_db),
        token: str = Depends(oauth2_scheme)
) -> models.User:
    try:
        payload = jwt.decode(
            token, security.SECRET_KEY,
            algorithms=[security.ALGORITHM]
        )
        token_data = schemas.TokenPayload(**payload)
    except (jwt.JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )
    user = crud.get_user(db=db, user_id=token_data.sub)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def get_current_active_user(
        current_user: models.User = Depends(get_current_user),
) -> models.User:
    if not crud.is_active(current_user):
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def get_current_active_admin(
        current_user: models.User = Depends(get_current_user)
) -> models.User:
    if not crud.is_admin(current_user):
        raise HTTPException(status_code=400, detail="You do not have an admin access")

    return current_user


"""
middleware logging
"""


async def set_body(request: Request, body: bytes):
    async def receive() :
        # print(f"body is {body}")
        return {"type": "http.request", "body": body}

    request._receive = receive


async def get_body(request: Request) -> bytes:
    body = await request.body()
    await set_body(request, body)
    return body


@app.middleware("http")
async def app_entry(request: Request, call_next):
    idem = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    logger.debug(f"rid={idem} start request path={request.url.path}")
    start_time = time.time()
    await set_body(request, await request.body())

    logger.warning(await get_body(request))
    b = await  get_body((request))


    # print(json.loads(b.decode('utf-8')))
    # st = b.decode('utf-8')
    # print(f" b is {st}")
    # print(st.split("&password")[0])
    loggin_info = b.decode('utf-8').split("&password")[0]
    # d = request.json()

    logger.info(
            f"{request.method} request to {request.url} "
            f"logging info: {loggin_info}"
            # f"\nHeaders: {request.headers}\n"
            # f"\n host in {'host' in request.headers}"
            # f"client: {request.client}"
            # # f"\tAuth: {request.auth}"
            # # f"\taccess_token: {request.access_token}"
            f"\nPath Params: {request.path_params}"
            f"\nQuery Params: {request.query_params}"
            f"\nCookies: {request.cookies}"
        )

    response = await call_next(request)

    res_body = b''

    response_body = [chunk async for chunk in response.body_iterator]
    # print("list is:", response_body)
    response.body_iterator = iterate_in_threadpool(iter(response_body))
    # print(f"response_body={response_body[0].decode()}")
    logger.info(f"response_body: {response_body[0].decode()}")

    # process_time = (time.time() - start_time) * 1000
    # formatted_process_time = '{0:.2f}'.format(process_time)
    # logger.debug(
    #     f"rid={idem} completed_in={formatted_process_time}ms status_code={response.status_code}  "
    #     f"headers = {response.headers}"
    # )
    # #
    return response

# @app.middleware("http")
# async def log_requests(request, call_next):
#     idem = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
#     logger.debug(f"rid={idem} start request path={request.url.path}")
#     start_time = time.time()
#
#     response = await call_next(request)
#
#     process_time = (time.time() - start_time) * 1000
#     formatted_process_time = '{0:.2f}'.format(process_time)
#     logger.debug(f"rid={idem} completed_in={formatted_process_time}ms status_code={response.status_code}")
#
#     return response


"""
Uvicorn logger
"""


########### UVICORN PART ##################


# @app.on_event("startup")
# async def startup_event():
#     logger = logging.getLogger("uvicorn.access")
#
#     handler = logging.handlers.RotatingFileHandler("api.log", mode="a", maxBytes=100 * 1024, backupCount=3)
#     handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s "))
#     logger.addHandler(handler)


"""
Create new user
"""


@app.post("/create-user", response_model=schemas.User)
def create_user(
        *,
        db: Session = Depends(get_db),
        email: str = Body(None),
        password: str = Body(None),

) -> Any:
    # print("Null is: ", email, password)
    # if not email or not password:
    #     raise HTTPException(status_code=400,
    #                         detail="Email and Password can not be empty.")
    db_user = crud.get_user_by_email(db, email=email)
    if db_user:
        logger.error(f"detail= Email already registered status code ={400}")
        raise HTTPException(status_code=400,
                            detail="Email already registered"
                            )
    user_in = schemas.CreateUser(password=password, email=email)
    db_user = crud.create_user(db=db, user=user_in)
    # return
    # FileResponse(some_file_path)

    return db_user


"""
Update the user
"""


@app.patch("/current-user/update",
           response_model=schemas.User,
           status_code=status.HTTP_201_CREATED)
def update_user_info(*,
                     db: Session = Depends(get_db),
                     password: str = Body(None),
                     email: str = Body(None),
                     current_user: models.User = Depends(get_current_active_user),
                     ) -> Any:
    print(" current_user", current_user)
    current_user_data = jsonable_encoder(current_user)
    print(" current_user_data ", current_user_data)
    user_in = schemas.UpdateUser(**current_user_data)
    print("user_in ", user_in)

    if password is not None:
        user_in.password = password
    if email is not None:
        user_in.email = email

    user = crud.update_user(
        db=db,
        db_user=current_user,
        user=user_in
    )

    return user


"""
Create items of a user
"""


@app.post("/current-user/create-items",
          response_model=Union[schemas.Item, None])
def create_item_for_user(*,
                         db: Session = Depends(get_db),
                         current_user: models.User = Depends(get_current_active_user),
                         item: schemas.ItemCreate,
                         ):
    db_item = crud.read_item_by_title(db=db, item_title=item.title)

    if db_item and (db_item.title, db_item.description, db_item.owner_id) == \
            (item.title, item.description, current_user.id):
        raise HTTPException(status_code=400, detail="This item already submitted for this user")

    # item.created_at = datetime.now()
    # print(jsonable_encoder(item) )

    return crud.create_user_item(db=db, item=item, owner_id=current_user.id)

    # item = crud.read_item_by_title(db=db, item_title=item_title)
    # if item:

    # return crud.create_user_item(db=db, item=itemcre, user_id=user_id)


"""
Retrieve items for current user
"""


@app.get("/current-user/items", response_model=list[schemas.Item])
def read_items_for_current_user(
        db: Session = Depends(get_db),
        skip: int = 0,
        limit: int = 100,
        current_user: models.User = Depends(get_current_active_user),
) -> Any:
    items = crud.get_items_of_the_user(db=db, owner_id=current_user.id, skip=skip, limit=limit)
    return items


"""
Retrive a specific user by id.
"""


@app.get("/users/{user_id}", response_model=schemas.User)
def read_user_by_id(
        user_id: int,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_active_admin)

) -> Any:
    db_user = crud.get_user(db=db, user_id=user_id)

    if db_user is None:
        raise HTTPException(status_code=404, detail=" User Not Found!")
    return db_user


@app.get("/users/read-users/", response_model=list[schemas.User])
def read_users(
        db: Session = Depends(get_db),

        skip: int = 0,
        limit: int = 100,
        current_user: models.User = Depends(get_current_active_admin),
):
    users = crud.get_users(db=db,
                           skip=skip, limit=limit)

    return users


"""
Delete a User
"""


@app.delete("/users/delete", response_model=schemas.User)
def delete_user_info(*,
                     user_id: int,
                     db: Session = Depends(get_db),
                     current_user: models.User = Depends(get_current_active_admin)
                     ):
    db_user = crud.get_user(db=db, user_id=user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    if crud.delete_user(user_id=user_id, db=db):
        raise HTTPException(status_code=200, detail="User Seccessfully deleted!")
    return db_user


############### Items #####################

"""
Create new item
"""


@app.post("/item/create", response_model=schemas.Item)
def create_item(*,
                db: Session = Depends(get_db),
                item_in: schemas.ItemCreate,
                current_user: models.User = Depends(get_current_active_user)
                ) -> Any:
    item = crud.create_user_item(db=db, item=item_in, owner_id=current_user.id)
    return item


"""
Retrieve items.
"""


@app.get("/items/read-items", response_model=list[schemas.Item])
# @app.get("/items/read-items", response_model=Union[list[schemas.Item], list[schemas.ItemBase]])
def read_items(
        db: Session = Depends(get_db),
        skip: int = 0,
        limit: int = 100,
        current_user: models.User = Depends(get_current_active_user)
) -> Any:
    # print(current_user.id, current_user.is_admin)
    if current_user.is_admin:
        # print("hi")
        items = crud.get_items(db=db, skip=skip, limit=limit)
        return items
    else:
        items = crud.get_items_of_the_user( \
            db=db, owner_id=current_user.id,
            skip=skip, limit=limit)

        return items


"""
Update an item.
"""


@app.patch("/items/update/{item_id}", response_model=schemas.Item)
def update_item_info(*,
                     db: Session = Depends(get_db),
                     item_id: int,
                     item_in: schemas.ItemUpdate,
                     current_user: models.User = Depends(get_current_active_admin),
                     ) -> Any:
    item = crud.get_item(db=db, item_id=item_id)
    print(jsonable_encoder(item))

    item.updated_at = datetime.now()
    print(jsonable_encoder(item))

    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    # item = crud.update_item(db=db, db_item=item, item=item_in)
    # item = crud.update_item(db=db, db_item=item, item=item_in, updated_at=datetime.now())
    item = crud.update_item(db=db, db_item=item, item=item_in)
    return item


"""
Delete an item.
"""


@app.delete("/items/delete", response_model=schemas.Item)
def delete_item_info(*,
                     db: Session = Depends(get_db),
                     current_user: models.User = Depends(get_current_active_admin),
                     item_id: int,
                     ) -> Any:
    item = crud.get_item(db=db, item_id=item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    if crud.delete_item(item_id=item_id, db=db):
        raise HTTPException(status_code=200, detail="Item Seccessfully deleted!")


################# Login ####################
"""
get an access token for future requests
"""


@app.post("/login/access-token", response_model=schemas.Token)
def login_access_token(
        db: Session = Depends(get_db),
        form_data: OAuth2PasswordRequestForm = Depends()
) -> Any:
    user = crud.user_authentication(
        db=db,
        email=form_data.username,
        password=form_data.password
    )
    if not user:
        raise HTTPException(status_code=400,
                            detail="Incorrect email or password")
    elif not crud.is_active(user=user):
        raise HTTPException(status_code=400,
                            detail="Inactive user")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    a = security.create_acees_token(
            sub=user.id,
            expires_delta=access_token_expires
        )
    # print(a)
    # logger.info(f"access token: {a}" )
    return {
        "access_token": a,
        "token_type": "bearer",
    }

    """

"""


@app.get("/items/search",
         response_model=schemas.Item)
def read_item_from_title(*,
                         db: Session = Depends(get_db),
                         item_title: str
                         ):
    return crud.read_item_by_title(db=db, item_title=item_title)

############################

