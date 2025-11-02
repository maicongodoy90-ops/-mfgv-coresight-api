from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text, Enum, Float
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import enum

Base = declarative_base()

class UserRole(str, enum.Enum):
    """Enumeração de papéis de usuário."""
    ADMIN = "admin"
    GESTOR = "gestor"
    COLABORADOR = "colaborador"

class User(Base):
    """Modelo de usuário para banco de dados."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    full_name = Column(String(100), nullable=True)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    role = Column(Enum(UserRole), default=UserRole.COLABORADOR)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<User(id={self.id}, username={self.username}, email={self.email}, role={self.role})>"

# ==================== MODELO DE PESQUISA ====================

class Survey(Base):
    """Modelo de Pesquisa de Endomarketing"""
    __tablename__ = "surveys"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)  # "Clima Organizacional 2025"
    description = Column(Text, nullable=True)
    status = Column(String(50), default="ativa")  # ativa, pausada, encerrada
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relacionamentos
    questions = relationship("SurveyQuestion", back_populates="survey", cascade="all, delete-orphan")
    responses = relationship("SurveyResponse", back_populates="survey", cascade="all, delete-orphan")


class SurveyQuestion(Base):
    """Modelo de Perguntas da Pesquisa"""
    __tablename__ = "survey_questions"
    
    id = Column(Integer, primary_key=True, index=True)
    survey_id = Column(Integer, ForeignKey("surveys.id"), nullable=False)
    question_text = Column(String(500), nullable=False)
    question_type = Column(String(50), default="likert")  # likert, aberta, multipla
    order = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relacionamentos
    survey = relationship("Survey", back_populates="questions")
    answers = relationship("SurveyAnswer", back_populates="question", cascade="all, delete-orphan")


class SurveyResponse(Base):
    """Modelo de Respostas da Pesquisa"""
    __tablename__ = "survey_responses"
    
    id = Column(Integer, primary_key=True, index=True)
    survey_id = Column(Integer, ForeignKey("surveys.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relacionamentos
    survey = relationship("Survey", back_populates="responses")
    answers = relationship("SurveyAnswer", back_populates="response", cascade="all, delete-orphan")


class SurveyAnswer(Base):
    """Modelo de Respostas Individuais"""
    __tablename__ = "survey_answers"
    
    id = Column(Integer, primary_key=True, index=True)
    response_id = Column(Integer, ForeignKey("survey_responses.id"), nullable=False)
    question_id = Column(Integer, ForeignKey("survey_questions.id"), nullable=False)
    answer_value = Column(Integer, nullable=True)  # Para escala Likert (1-5)
    answer_text = Column(Text, nullable=True)  # Para respostas abertas
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relacionamentos
    response = relationship("SurveyResponse", back_populates="answers")
    question = relationship("SurveyQuestion", back_populates="answers")

# ==================== MODELO DE RECOMENDAÇÕES ====================

class SurveyRecommendation(Base):
    """Modelo de Recomendações Automáticas"""
    __tablename__ = "survey_recommendations"
    
    id = Column(Integer, primary_key=True, index=True)
    survey_id = Column(Integer, ForeignKey("surveys.id"), nullable=False)
    recommendation_text = Column(Text, nullable=False)
    priority = Column(String(20), nullable=False)  # high, medium, low
    category = Column(String(50), nullable=False)  # culture, leadership, competence, engagement
    score = Column(Float, nullable=False)  # 0-10
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relacionamentos
    survey = relationship("Survey", foreign_keys=[survey_id])

class SurveyKPI(Base):
    """Modelo de KPIs Calculados"""
    __tablename__ = "survey_kpis"
    
    id = Column(Integer, primary_key=True, index=True)
    survey_id = Column(Integer, ForeignKey("surveys.id"), nullable=False)
    category = Column(String(50), nullable=False)  # categoria da pergunta
    score = Column(Float, nullable=False)  # média 0-10
    total_responses = Column(Integer, default=0)
    trend = Column(String(20), default="stable")  # up, down, stable
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relacionamentos
    survey = relationship("Survey", foreign_keys=[survey_id])


