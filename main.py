from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from dotenv import load_dotenv
import os
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import logging
from loguru import logger

# ==================== IMPORTS ====================
from models import User, Base
from auth import get_password_hash
from db import engine
import schemas
import auth

logger.add("logs/info.log", rotation="1 week", retention="4 weeks", level="INFO")

# Carregar variáveis de ambiente
load_dotenv()

# Configurações
DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL não foi configurada")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY não foi configurada")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Criar aplicação FastAPI
app = FastAPI(
    title="MFGV CoreSight API",
    description="API de Endomarketing com Autenticação JWT",
    version="1.0.0"
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== DEPENDENCY ====================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ==================== ROTAS BÁSICAS ====================

@app.get("/", tags=["Health Check"])
async def root():
    return {
        "message": "✅ API MFGV CoreSight está rodando!",
        "status": "online",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health", tags=["Health Check"])
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }

# ==================== AUTENTICAÇÃO ====================

@app.post("/api/auth/register", response_model=schemas.Token, tags=["Authentication"])
def register(user_data: schemas.UserCreate, db: Session = Depends(get_db)):
    try:
        db_user = auth.create_user(
            db=db,
            username=user_data.username,
            email=user_data.email,
            password=user_data.password,
            full_name=user_data.full_name
        )
        
        access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = auth.create_access_token(
            data={"sub": db_user.username, "user_id": db_user.id, "role": db_user.role.value},
            expires_delta=access_token_expires
        )
        
        logger.info(f"✅ Novo usuário registrado: {db_user.username}")
        
        return schemas.Token(
            access_token=access_token,
            token_type="bearer",
            expires_in=auth.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=db_user
        )
    except HTTPException as e:
        logger.error(f"❌ Erro ao registrar: {e.detail}")
        raise
    except Exception as e:
        logger.error(f"❌ Erro inesperado ao registrar: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@app.post("/api/auth/login", response_model=schemas.Token, tags=["Authentication"])
def login(user_credentials: schemas.UserLogin, db: Session = Depends(get_db)):
    try:
        user = auth.authenticate_user(
            db=db,
            username=user_credentials.username,
            password=user_credentials.password
        )
        
        if not user:
            logger.warning(f"❌ Tentativa de login inválida: {user_credentials.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Username ou senha incorretos",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = auth.create_access_token(
            data={"sub": user.username, "user_id": user.id, "role": user.role.value},
            expires_delta=access_token_expires
        )
        
        logger.info(f"✅ Login bem-sucedido: {user.username}")
        
        return schemas.Token(
            access_token=access_token,
            token_type="bearer",
            expires_in=auth.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=user
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erro inesperado ao fazer login: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@app.get("/api/auth/me", response_model=schemas.UserResponse, tags=["Authentication"])
def get_me(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        user = auth.get_current_user(token, db)
        logger.info(f"✅ Informações do usuário obtidas: {user.username}")
        return user
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erro ao obter informações do usuário: {str(e)}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Erro ao verificar autenticação")

@app.post("/api/auth/refresh", response_model=schemas.Token, tags=["Authentication"])
def refresh(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        user = auth.get_current_user(token, db)
        
        access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = auth.create_access_token(
            data={"sub": user.username, "user_id": user.id, "role": user.role.value},
            expires_delta=access_token_expires
        )
        
        logger.info(f"✅ Token renovado para: {user.username}")
        
        return schemas.Token(
            access_token=access_token,
            token_type="bearer",
            expires_in=auth.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=user
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erro ao renovar token: {str(e)}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Erro ao renovar token")

# ==================== SETUP ADMIN ====================

@app.post("/admin-setup", tags=["Setup"])
def criar_admin(db: Session = Depends(get_db)):
    """Cria o usuário admin padrão (rodar uma única vez!)"""
    
    try:
        # Verifica se já existe admin
        admin_existe = db.query(User).filter(User.email == "admin@test.com").first()
        if admin_existe:
            return {"msg": "Admin já existe!"}
        
        # Cria novo admin
        novo_admin = User(
            username="admin",
            email="admin@test.com",
            full_name="Administrador",
            hashed_password=get_password_hash("admin123"),
            is_active=True,
            role="admin"
        )
        db.add(novo_admin)
        db.commit()
        db.refresh(novo_admin)
        
        logger.info(f"✅ Admin criado com sucesso")
        return {"msg": "Admin criado com sucesso!", "email": "admin@test.com", "password": "admin123"}
    
    except Exception as e:
        db.rollback()
        logger.error(f"❌ Erro ao criar admin: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

# ==================== STARTUP/SHUTDOWN ====================

@app.on_event("startup")
async def startup_event():
    logger.info("🚀 API iniciando...")
    logger.info("✅ API pronta para receber requisições!")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("🛑 API encerrando...")

# ==================== TRATAMENTO DE ERROS ====================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    logger.error(f"HTTP Error: {exc.status_code} - {exc.detail}")
    return {
        "error": exc.detail,
        "status_code": exc.status_code,
        "timestamp": datetime.now().isoformat()
    }

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error(f"Erro não tratado: {str(exc)}")
    return {
        "error": "Erro interno do servidor",
        "status_code": 500,
        "timestamp": datetime.now().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True, log_level="info")
