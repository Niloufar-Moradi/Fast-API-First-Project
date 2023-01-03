# from . import models
# from fastapi import FastAPI, Depends, HTTPException, Body, status


# def get_current_user(
#     db:sess
# )


# def get_current_active_user(
#     current_user: models.User = Depends(get_current_user),
# ) -> models.User:
#     if not crud.user.is_active(current_user):
#         raise HTTPException(status_code=400, detail="Inactive user")
#     return current_user
