# === FOLDER STRUCTURE ===
# backend/
# ├── app/
# │   ├── main.py
# │   ├── models.py
# │   ├── schemas.py
# │   ├── database.py
# │   ├── auth.py
# │   ├── crud.py
# │   ├── deps.py
# │   ├── routers/
# │   │   ├── users.py
# │   │   ├── purchases.py
# │   │   ├── transfers.py
# │   │   ├── assignments.py
# │   │   ├── dashboard.py
# │   │   └── login.py
# ├── requirements.txt
# └── .env

# === FILE: backend/app/database.py ===
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# === FILE: backend/app/models.py ===
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    email = Column(String, unique=True)
    hashed_password = Column(String)
    role = Column(String)  # 'admin', 'commander', 'logistics'
    base_id = Column(Integer, ForeignKey("bases.id"))

class BaseModel(Base):
    __tablename__ = "bases"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    location = Column(String)

class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    type = Column(String)

class Inventory(Base):
    __tablename__ = "inventory"
    id = Column(Integer, primary_key=True)
    base_id = Column(Integer, ForeignKey("bases.id"))
    asset_id = Column(Integer, ForeignKey("assets.id"))
    opening_balance = Column(Integer)
    closing_balance = Column(Integer)
    assigned = Column(Integer)
    expended = Column(Integer)
    created_at = Column(DateTime, default=func.now())

class Purchase(Base):
    __tablename__ = "purchases"
    id = Column(Integer, primary_key=True)
    base_id = Column(Integer, ForeignKey("bases.id"))
    asset_id = Column(Integer, ForeignKey("assets.id"))
    quantity = Column(Integer)
    purchase_date = Column(DateTime, default=func.now())

class Transfer(Base):
    __tablename__ = "transfers"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    from_base_id = Column(Integer, ForeignKey("bases.id"))
    to_base_id = Column(Integer, ForeignKey("bases.id"))
    quantity = Column(Integer)
    transfer_date = Column(DateTime, default=func.now())

class Assignment(Base):
    __tablename__ = "assignments"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    personnel_name = Column(String)
    base_id = Column(Integer, ForeignKey("bases.id"))
    quantity = Column(Integer)
    assigned_date = Column(DateTime, default=func.now())

class Expenditure(Base):
    __tablename__ = "expenditures"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    base_id = Column(Integer, ForeignKey("bases.id"))
    quantity = Column(Integer)
    expended_date = Column(DateTime, default=func.now())

class Log(Base):
    __tablename__ = "logs"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    action_type = Column(String)
    data = Column(JSON)
    timestamp = Column(DateTime, default=func.now())

# === FILE: backend/app/schemas.py ===
from pydantic import BaseModel
from typing import Optional

class UserCreate(BaseModel):
    name: str
    email: str
    password: str
    role: str
    base_id: Optional[int]

class UserOut(BaseModel):
    id: int
    name: str
    email: str
    role: str
    base_id: Optional[int]
    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class LoginData(BaseModel):
    username: str
    password: str

# === FILE: backend/app/auth.py ===
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException, status
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from .models import User
from .database import SessionLocal
import os

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")
SECRET_KEY = os.getenv("SECRET_KEY", "testsecret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    db = SessionLocal()
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.id == int(user_id)).first()
    if user is None:
        raise credentials_exception
    return user

# === FILE: backend/app/main.py ===
from fastapi import FastAPI
from .database import engine, Base
from .routers import users, purchases, transfers, assignments, dashboard, login

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.include_router(users.router)
app.include_router(purchases.router)
app.include_router(transfers.router)
app.include_router(assignments.router)
app.include_router(dashboard.router)
app.include_router(login.router)

# === FILE: backend/requirements.txt ===
fastapi
uvicorn
sqlalchemy
psycopg2-binary
python-dotenv
passlib[bcrypt]
jose
pydantic

# === FILE: backend/.env ===
DATABASE_URL=postgresql://username:password@localhost:5432/military_assets
SECRET_KEY=your_secret_key_here
