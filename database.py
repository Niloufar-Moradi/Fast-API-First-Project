from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
# from sqlalchemy_utils import database_exists, create_database



## Create a database URL for SQLAlchemy
# SQLALCHEMY_DATABASE_URL = "postgresql+psycopg2://postgres:AlgorEx%24S%40h%401401@192.168.1.115:5440/fastapi"

SQLALCHEMY_DATABASE_URL = "postgresql+psycopg2://postgres:2024@localhost:5432/postgres"

##  create a SQLAlchemy "engine".
engine = create_engine(

    SQLALCHEMY_DATABASE_URL,  pool_pre_ping=True, 

    connect_args={
            "keepalives": 1,
            "keepalives_idle": 130,
            "keepalives_interval": 10,
            "keepalives_count": 15,
        }

)

## each instance of SessionLocal class would be a database session 
SessionLocal = sessionmaker(autocommit = False, autoflush=False, bind=engine)


## to create each database models and classes it returns a class, later we inherit from it in models.py
Base = declarative_base()
