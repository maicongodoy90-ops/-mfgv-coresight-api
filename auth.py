from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status, APIRouter, Depends, Body
from sqlalchemy.orm import Session
import logging
import os
from dotenv import load_dotenv
from pydantic import BaseModel
from db import get_db
from models import User


load_dotenv()
logger = logging.getLogger(__name__)

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
router = APIRouter()

# ==================== SCHEMAS ====================

class LoginRequest(BaseModel):
    email: str
    password: str

# ==================== FUNÇÕES DE SENHA ====================

def get_password_hash(password: str) -> str:
    """Criar hash da senha."""
    if len(password) > 72:
        password = password[:72]
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verificar senha."""
    if len(plain_password) > 72:
        plain_password = plain_password[:72]
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except:
        return False

# ==================== FUNÇÕES DE TOKEN ====================

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Criar token JWT."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    
    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    except Exception as e:
        logger.error(f"Erro ao criar token: {str(e)}")
        raise

def verify_token(token: str) -> dict:
    """Verificar token JWT."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")

# ==================== FUNÇÕES DE USUÁRIO ====================

def get_user_by_username(db: Session, username: str):
    """Buscar usuário por username."""
    from models import User
    return db.query(User).filter(User.username == username).first()

def get_user_by_email(db: Session, email: str):
    """Buscar usuário por email."""
    from models import User
    return db.query(User).filter(User.email == email).first()

def create_user(db: Session, username: str, email: str, password: str, full_name: str = None):
    """Criar novo usuário."""
    from models import User
    
    if get_user_by_username(db, username):
        raise HTTPException(status_code=400, detail="Usuário já existe")
    
    if get_user_by_email(db, email):
        raise HTTPException(status_code=400, detail="Email já existe")
    
    hashed_password = get_password_hash(password)
    new_user = User(
        username=username,
        email=email,
        full_name=full_name,
        hashed_password=hashed_password
    )
    
    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return new_user
    except Exception as e:
        db.rollback()
        logger.error(f"Erro ao criar usuário: {str(e)}")
        raise HTTPException(status_code=500, detail="Erro ao criar usuário")

def authenticate_user(db: Session, username: str, password: str):
    """Autenticar usuário."""
    user = get_user_by_username(db, username)
    
    if not user or not verify_password(password, user.hashed_password) or not user.is_active:
        return None
    
    return user

def get_current_user(token: str, db: Session):
    """Obter usuário atual."""
    try:
        payload = verify_token(token)
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Token inválido")
        
        user = get_user_by_username(db, username)
        if not user:
            raise HTTPException(status_code=401, detail="Usuário não encontrado")
        
        return user
    except:
        raise HTTPException(status_code=401, detail="Erro na autenticação")

# ==================== ENDPOINTS ====================

@router.post("/api/auth/login")
def login(credentials: LoginRequest, db: Session = Depends(get_db)):
    """Login com email e senha"""

    
    # Buscar usuário por EMAIL
    user = db.query(User).filter(User.email == credentials.email).first()
    
    # Verificar se usuário existe e senha está correta
    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Email ou senha inválidos")
    
    # Criar token
    access_token = create_access_token({"sub": user.username})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "email": user.email,
        "username": user.username
    }

