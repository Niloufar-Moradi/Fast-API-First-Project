### SQLAlchemy models ###

from sqlalchemy import Boolean, String, Integer, ForeignKey, Column, TIMESTAMP
from sqlalchemy.orm import relationship

from .database import Base





class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    ## Relationship connection  between tables: (provided by sqlalchemy ORM)

    items = relationship("Item", back_populates="owner", cascade="all, delete-orphan")




class Item(Base):
    __tablename__ = "items"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String, index=True)
    # owner_id = Column(Integer, ForeignKey("users.id", ondelete="cascade"))
    owner_id = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(TIMESTAMP)
    created_at = Column(TIMESTAMP)
    # owner = relationship("User", back_populates="items" , cascade="all, delete")
    owner = relationship("User", back_populates="items" )

    
