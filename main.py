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
from surveys import router as surveys_router
import logging

import schemas
import auth
from models import Base

from loguru import logger
logger.add("logs/info.log", rotation="1 week", retention="4 weeks", level="INFO")

from auth import router as auth_router
from calculo import router as calculo_router
# Adicione outros módulos/routers que você tenha, por exemplo:
# from surveys import router as surveys_router
# from analytics import router as analytics_router


# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Carregar variáveis de ambiente
load_dotenv()

# Configurações
DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")

# Validar se DATABASE_URL existe
if not DATABASE_URL:
    raise ValueError("DATABASE_URL não foi configurada no arquivo .env")

if not SECRET_KEY:
    raise ValueError("SECRET_KEY não foi configurada no arquivo .env")

# Criar engine do banco de dados
engine = create_engine(
    DATABASE_URL,
    echo=True,
    pool_size=10,
    max_overflow=20
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Contexto de criptografia de senha
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Criar aplicação FastAPI
app = FastAPI(
    title="MFGV CoreSight API",
    description="API de Endomarketing com Autenticação JWT e PostgreSQL",
    version="1.0.0"
)

# Esquema OAuth2 para autenticação
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# Configurar CORS (permitir requisições de frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependency para pegar a sessão do banco
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ==================== ROTAS BÁSICAS ====================

@app.get("/", tags=["Health Check"])
async def root():
    """Rota raiz para verificar se a API está rodando."""
    return {
        "message": "✅ API MFGV CoreSight está rodando!",
        "status": "online",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health", tags=["Health Check"])
async def health_check():
    """Verificar saúde da API."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }

# ==================== ROTAS DE TESTE ====================

@app.get("/api/test", tags=["Test"])
async def test_route():
    """Rota de teste simples."""
    return {
        "message": "Teste bem-sucedido!",
        "database": "Conectado ao PostgreSQL via AIVEN"
    }

@app.get("/api/info", tags=["Info"])
async def api_info():
    """Informações da API."""
    return {
        "api_name": "MFGV CoreSight",
        "api_version": "1.0.0",
        "description": "Sistema de Endomarketing com Autenticação JWT",
        "database": "PostgreSQL AIVEN",
        "authentication": "JWT Bearer Tokens",
        "timestamp": datetime.now().isoformat()
    }

# ==================== ROTAS DE AUTENTICAÇÃO ====================

@app.post("/api/auth/register", response_model=schemas.Token, tags=["Authentication"])
def register(user_data: schemas.UserCreate, db: Session = Depends(get_db)):
    """Registrar novo usuário."""
    try:
        # Criar novo usuário
        db_user = auth.create_user(
            db=db,
            username=user_data.username,
            email=user_data.email,
            password=user_data.password,
            full_name=user_data.full_name
        )
        
        # Criar token JWT
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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.post("/api/auth/login", response_model=schemas.Token, tags=["Authentication"])
def login(user_credentials: schemas.UserLogin, db: Session = Depends(get_db)):
    """Fazer login com username e senha."""
    try:
        # Autenticar usuário
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
        
        # Criar token JWT
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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.get("/api/auth/me", response_model=schemas.UserResponse, tags=["Authentication"])
def get_me(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Obter informações do usuário autenticado."""
    try:
        user = auth.get_current_user(token, db)
        logger.info(f"✅ Informações do usuário obtidas: {user.username}")
        return user
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erro ao obter informações do usuário: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Erro ao verificar autenticação"
        )

@app.post("/api/auth/refresh", response_model=schemas.Token, tags=["Authentication"])
def refresh(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Renovar o token JWT."""
    try:
        user = auth.get_current_user(token, db)
        
        # Criar novo token
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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Erro ao renovar token"
        )

# ==================== TRATAMENTO DE ERROS ====================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Handler para exceções HTTP."""
    logger.error(f"HTTP Error: {exc.status_code} - {exc.detail}")
    return {
        "error": exc.detail,
        "status_code": exc.status_code,
        "timestamp": datetime.now().isoformat()
    }

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handler para exceções gerais."""
    logger.error(f"Erro não tratado: {str(exc)}")
    return {
        "error": "Erro interno do servidor",
        "status_code": 500,
        "timestamp": datetime.now().isoformat()
    }

# ==================== EVENTO DE STARTUP ====================

@app.on_event("startup")
async def startup_event():
    """Executar quando a API inicia."""
    logger.info("🚀 API iniciando...")
    logger.info(f"🗄️  Banco de dados: {DATABASE_URL.split('@')[1] if '@' in DATABASE_URL else 'Configurado'}")
    logger.info("✅ API pronta para receber requisições!")

@app.on_event("shutdown")
async def shutdown_event():
    """Executar quando a API encerra."""
    logger.info("🛑 API encerrando...")

# ==================== FUNÇÃO PARA CRIAR CHAVE SEGURA ====================

def get_password_hash(password: str) -> str:
    """Criar hash da senha."""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verificar se a senha corresponde ao hash."""
    return pwd_context.verify(plain_password, hashed_password)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info"
    )
# ==================== ENDPOINTS DE PESQUISA ====================

from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

@app.post("/api/surveys/create", tags=["Surveys"])
def create_survey(
    survey_data: schemas.SurveyCreate,
    db: Session = Depends(get_db)
):
    """Criar nova pesquisa de endomarketing"""
    try:
        # Criar pesquisa
        db_survey = models.Survey(
            title=survey_data.title,
            description=survey_data.description,
            created_by_id=1
        )
        db.add(db_survey)
        db.flush()
        
        # Adicionar perguntas
        for q in survey_data.questions:
            question = models.SurveyQuestion(
                survey_id=db_survey.id,
                question_text=q.question_text,
                question_type=q.question_type,
                order=q.order
            )
            db.add(question)
        
        db.commit()
        db.refresh(db_survey)
        
        logger.info(f"✅ Pesquisa criada: {db_survey.id}")
        return {"message": "Pesquisa criada com sucesso", "survey_id": db_survey.id}
    
    except Exception as e:
        db.rollback()
        logger.error(f"❌ Erro ao criar pesquisa: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/surveys", tags=["Surveys"])
def list_surveys(
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 10
):
    """Listar todas as pesquisas ativas"""
    try:
        surveys = db.query(models.Survey)\
            .filter(models.Survey.status == "ativa")\
            .offset(skip)\
            .limit(limit)\
            .all()
        
        logger.info(f"📋 {len(surveys)} pesquisas listadas")
        return surveys
    
    except Exception as e:
        logger.error(f"❌ Erro ao listar pesquisas: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/surveys/{survey_id}", tags=["Surveys"])
def get_survey(
    survey_id: int,
    db: Session = Depends(get_db)
):
    """Obter detalhes de uma pesquisa"""
    try:
        survey = db.query(models.Survey).filter(models.Survey.id == survey_id).first()
        
        if not survey:
            raise HTTPException(status_code=404, detail="Pesquisa não encontrada")
        
        logger.info(f"🔍 Pesquisa {survey_id} obtida")
        return survey
    
    except Exception as e:
        logger.error(f"❌ Erro ao obter pesquisa: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/surveys/{survey_id}/submit", tags=["Surveys"])
def submit_survey_response(
    survey_id: int,
    submission: schemas.SurveySubmit,
    db: Session = Depends(get_db)
):
    """Submeter respostas de uma pesquisa"""
    try:
        # Validar pesquisa
        survey = db.query(models.Survey).filter(models.Survey.id == survey_id).first()
        if not survey:
            raise HTTPException(status_code=404, detail="Pesquisa não encontrada")
        
        # Criar resposta
        response = models.SurveyResponse(
            survey_id=survey_id,
            user_id=1
        )
        db.add(response)
        db.flush()
        
        # Adicionar respostas individuais
        for answer in submission.answers:
            db_answer = models.SurveyAnswer(
                response_id=response.id,
                question_id=answer.question_id,
                answer_value=answer.answer_value,
                answer_text=answer.answer_text
            )
            db.add(db_answer)
        
        db.commit()
        db.refresh(response)
        
        logger.info(f"✅ Resposta submetida para pesquisa {survey_id}")
        return {"message": "Respostas salvas com sucesso", "response_id": response.id}
    
    except Exception as e:
        db.rollback()
        logger.error(f"❌ Erro ao submeter respostas: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/surveys/{survey_id}/results", tags=["Surveys"])
def get_survey_results(
    survey_id: int,
    db: Session = Depends(get_db)
):
    """Obter resultados agregados da pesquisa"""
    try:
        survey = db.query(models.Survey).filter(models.Survey.id == survey_id).first()
        if not survey:
            raise HTTPException(status_code=404, detail="Pesquisa não encontrada")
        
        # Contar respostas
        total_responses = db.query(models.SurveyResponse)\
            .filter(models.SurveyResponse.survey_id == survey_id)\
            .count()
        
        # Calcular média por pergunta
        questions_stats = []
        for question in survey.questions:
            answers = db.query(models.SurveyAnswer)\
                .filter(models.SurveyAnswer.question_id == question.id)\
                .all()
            
            if answers:
                valid_answers = [a.answer_value for a in answers if a.answer_value]
                avg_value = sum(valid_answers) / len(valid_answers) if valid_answers else 0
            else:
                avg_value = 0
            
            questions_stats.append({
                "question_id": question.id,
                "question_text": question.question_text,
                "average": round(avg_value, 2),
                "total_answers": len(answers)
            })
        
        logger.info(f"📊 Resultados da pesquisa {survey_id} obtidos")
        return {
            "survey_id": survey_id,
            "survey_title": survey.title,
            "total_responses": total_responses,
            "questions_stats": questions_stats
        }
    
    except Exception as e:
        logger.error(f"❌ Erro ao obter resultados: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# ==================== ENDPOINTS DE CÁLCULO E KPIs ====================

@app.post("/api/surveys/{survey_id}/calculate-kpis", tags=["Analytics"])
def calculate_survey_kpis(
    survey_id: int,
    db: Session = Depends(get_db)
):
    """Calcular KPIs automáticos da pesquisa"""
    try:
        survey = db.query(models.Survey).filter(models.Survey.id == survey_id).first()
        if not survey:
            raise HTTPException(status_code=404, detail="Pesquisa não encontrada")
        
        # Limpar KPIs antigos
        db.query(models.SurveyKPI).filter(models.SurveyKPI.survey_id == survey_id).delete()
        
        # Calcular por categoria
        categories = {}
        
        for question in survey.questions:
            category = question.question_type
            
            answers = db.query(models.SurveyAnswer)\
                .filter(models.SurveyAnswer.question_id == question.id)\
                .all()
            
            if answers:
                valid_answers = [a.answer_value for a in answers if a.answer_value]
                if valid_answers:
                    avg = sum(valid_answers) / len(valid_answers)
                    score = (avg / 5) * 10  # Converter de 1-5 para 0-10
                    
                    if category not in categories:
                        categories[category] = {"scores": [], "count": 0}
                    
                    categories[category]["scores"].append(score)
                    categories[category]["count"] = len(valid_answers)
        
        # Salvar KPIs no banco
        kpis_list = []
        for cat_name, cat_data in categories.items():
            if cat_data["scores"]:
                final_score = sum(cat_data["scores"]) / len(cat_data["scores"])
                
                kpi = models.SurveyKPI(
                    survey_id=survey_id,
                    category=cat_name,
                    score=round(final_score, 2),
                    total_responses=cat_data["count"],
                    trend="stable"
                )
                db.add(kpi)
                kpis_list.append({
                    "category": cat_name,
                    "score": round(final_score, 2),
                    "total_responses": cat_data["count"]
                })
        
        db.commit()
        
        logger.info(f"✅ KPIs calculados para pesquisa {survey_id}")
        return {
            "message": "KPIs calculados com sucesso",
            "survey_id": survey_id,
            "kpis": kpis_list
        }
    
    except Exception as e:
        db.rollback()
        logger.error(f"❌ Erro ao calcular KPIs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/surveys/{survey_id}/generate-recommendations", tags=["Analytics"])
def generate_recommendations(
    survey_id: int,
    db: Session = Depends(get_db)
):
    """Gerar recomendações automáticas baseado nos KPIs"""
    try:
        survey = db.query(models.Survey).filter(models.Survey.id == survey_id).first()
        if not survey:
            raise HTTPException(status_code=404, detail="Pesquisa não encontrada")
        
        # Limpar recomendações antigas
        db.query(models.SurveyRecommendation).filter(
            models.SurveyRecommendation.survey_id == survey_id
        ).delete()
        
        # Obter KPIs
        kpis = db.query(models.SurveyKPI).filter(models.SurveyKPI.survey_id == survey_id).all()
        
        recommendations = []
        
        # Lógica de recomendações baseada em scores
        for kpi in kpis:
            if kpi.score < 4:
                priority = "high"
                emoji = "🔴"
                text = f"{emoji} AÇÃO URGENTE: {kpi.category} com score crítico ({kpi.score}/10). Intervir imediatamente!"
            elif kpi.score < 6:
                priority = "medium"
                emoji = "🟡"
                text = f"{emoji} MELHORIA NECESSÁRIA: {kpi.category} precisa de atenção ({kpi.score}/10)."
            elif kpi.score < 8:
                priority = "low"
                emoji = "🟢"
                text = f"{emoji} BOM: {kpi.category} está em bom nível ({kpi.score}/10)."
            else:
                priority = "low"
                emoji = "💚"
                text = f"{emoji} EXCELENTE: {kpi.category} está excelente ({kpi.score}/10)!"
            
            rec = models.SurveyRecommendation(
                survey_id=survey_id,
                recommendation_text=text,
                priority=priority,
                category=kpi.category,
                score=kpi.score
            )
            db.add(rec)
            recommendations.append({
                "category": kpi.category,
                "recommendation": text,
                "priority": priority,
                "score": kpi.score
            })
        
        db.commit()
        
        logger.info(f"✅ Recomendações geradas para pesquisa {survey_id}")
        return {
            "message": "Recomendações geradas com sucesso",
            "survey_id": survey_id,
            "total_recommendations": len(recommendations),
            "recommendations": recommendations
        }
    
    except Exception as e:
        db.rollback()
        logger.error(f"❌ Erro ao gerar recomendações: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/surveys/{survey_id}/analysis", tags=["Analytics"])
def get_full_analysis(
    survey_id: int,
    db: Session = Depends(get_db)
):
    """Obter análise completa da pesquisa com KPIs e recomendações"""
    try:
        survey = db.query(models.Survey).filter(models.Survey.id == survey_id).first()
        if not survey:
            raise HTTPException(status_code=404, detail="Pesquisa não encontrada")
        
        # Obter total de respostas
        total_responses = db.query(models.SurveyResponse)\
            .filter(models.SurveyResponse.survey_id == survey_id)\
            .count()
        
        # Obter KPIs
        kpis = db.query(models.SurveyKPI).filter(models.SurveyKPI.survey_id == survey_id).all()
        
        if not kpis:
            # Se não houver KPIs, calcular automaticamente
            logger.info(f"Calculando KPIs para pesquisa {survey_id}...")
            # Chamar função de cálculo
            categories = {}
            for question in survey.questions:
                category = question.question_type
                answers = db.query(models.SurveyAnswer)\
                    .filter(models.SurveyAnswer.question_id == question.id)\
                    .all()
                
                if answers:
                    valid_answers = [a.answer_value for a in answers if a.answer_value]
                    if valid_answers:
                        avg = sum(valid_answers) / len(valid_answers)
                        score = (avg / 5) * 10
                        
                        if category not in categories:
                            categories[category] = {"scores": [], "count": 0}
                        
                        categories[category]["scores"].append(score)
                        categories[category]["count"] = len(valid_answers)
            
            for cat_name, cat_data in categories.items():
                if cat_data["scores"]:
                    final_score = sum(cat_data["scores"]) / len(cat_data["scores"])
                    kpi = models.SurveyKPI(
                        survey_id=survey_id,
                        category=cat_name,
                        score=round(final_score, 2),
                        total_responses=cat_data["count"]
                    )
                    db.add(kpi)
            db.commit()
            kpis = db.query(models.SurveyKPI).filter(models.SurveyKPI.survey_id == survey_id).all()
        
        # Obter recomendações
        recommendations = db.query(models.SurveyRecommendation)\
            .filter(models.SurveyRecommendation.survey_id == survey_id)\
            .all()
        
        # Calcular score médio
        average_score = sum([kpi.score for kpi in kpis]) / len(kpis) if kpis else 0
        
        # Determinar status geral
        if average_score >= 8:
            status = "excellent"
        elif average_score >= 6:
            status = "good"
        else:
            status = "needs_improvement"
        
        kpi_list = [{
            "category": kpi.category,
            "score": kpi.score,
            "total_responses": kpi.total_responses,
            "trend": kpi.trend
        } for kpi in kpis]
        
        rec_list = [{
            "id": rec.id,
            "recommendation_text": rec.recommendation_text,
            "priority": rec.priority,
            "category": rec.category,
            "score": rec.score
        } for rec in recommendations]
        
        logger.info(f"📊 Análise completa obtida para pesquisa {survey_id}")
        return {
            "survey_id": survey_id,
            "survey_title": survey.title,
            "total_responses": total_responses,
            "average_score": round(average_score, 2),
            "status": status,
            "kpis": kpi_list,
            "recommendations": rec_list
        }
    
    except Exception as e:
        logger.error(f"❌ Erro ao obter análise: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from calculo import router as calculo_router


app = FastAPI()

app.include_router(surveys_router)
app.include_router(auth_router)
app.include_router(calculo_router)
# E para cada módulo, repita:
# app.include_router(surveys_router)
# app.include_router(analytics_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Troque pelo domínio real na produção!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(calculo_router)
from calculo import router as calculo_router
app.include_router(calculo_router)
from analytics import router as analytics_router
app.include_router(analytics_router)
from recommendations import router as recommendations_router
app.include_router(recommendations_router)

from fastapi import FastAPI
from db import engine
from models import Base

app = FastAPI()  # Se não existir, use o nome do seu app

@app.get("/criar-tabelas")
def criar_tabelas():
    Base.metadata.create_all(bind=engine)
    return {"msg": "Tabelas criadas na nuvem!"}
