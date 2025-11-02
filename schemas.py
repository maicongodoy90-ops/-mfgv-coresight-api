from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional
from enum import Enum

class UserRole(str, Enum):
    """Papéis disponíveis."""
    ADMIN = "admin"
    GESTOR = "gestor"
    COLABORADOR = "colaborador"

# ==================== SCHEMAS DE USUÁRIO ====================

class UserBase(BaseModel):
    """Schema base com campos comuns de usuário."""
    username: str = Field(..., min_length=3, max_length=50, description="Nome de usuário único")
    email: EmailStr = Field(..., description="Email válido e único")
    full_name: Optional[str] = Field(None, max_length=100, description="Nome completo")

class UserCreate(UserBase):
    """Schema para criação de novo usuário."""
    password: str = Field(..., min_length=8, description="Senha (mínimo 8 caracteres)")

class UserUpdate(BaseModel):
    """Schema para atualização de usuário."""
    full_name: Optional[str] = Field(None, max_length=100)
    email: Optional[EmailStr] = None

class UserResponse(UserBase):
    """Schema de resposta do usuário (sem senha)."""
    id: int
    is_active: bool
    role: UserRole
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class UserLogin(BaseModel):
    """Schema para login."""
    username: str = Field(..., min_length=3, description="Nome de usuário")
    password: str = Field(..., min_length=8, description="Senha")

# ==================== SCHEMAS DE TOKEN ====================

class Token(BaseModel):
    """Schema de resposta de token JWT."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse

class TokenData(BaseModel):
    """Schema de dados contidos no token."""
    username: Optional[str] = None
    user_id: Optional[int] = None
    role: Optional[str] = None

# ==================== SCHEMAS DE RESPOSTA ====================

class MessageResponse(BaseModel):
    """Schema genérico de resposta com mensagem."""
    message: str
    status_code: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class ErrorResponse(BaseModel):
    """Schema para resposta de erro."""
    error: str
    status_code: int
    detail: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

from typing import Optional, List
from datetime import datetime

# ==================== SCHEMAS DE PESQUISA ====================

class SurveyQuestionCreate(BaseModel):
    """Schema para criar pergunta"""
    question_text: str
    question_type: str = "likert"
    order: int


class SurveyCreate(BaseModel):
    """Schema para criar pesquisa"""
    title: str
    description: Optional[str] = None
    questions: List[SurveyQuestionCreate]


class SurveyResponse(BaseModel):
    """Schema de resposta da pesquisa"""
    id: int
    title: str
    description: Optional[str]
    status: str
    created_at: datetime
    
    class Config:
        from_attributes = True


class AnswerCreate(BaseModel):
    """Schema para responder uma pergunta"""
    question_id: int
    answer_value: Optional[int] = None
    answer_text: Optional[str] = None


class SurveySubmit(BaseModel):
    """Schema para submeter respostas"""
    survey_id: int
    answers: List[AnswerCreate]

# ==================== SCHEMAS DE KPI E RECOMENDAÇÕES ====================

class KPIResponse(BaseModel):
    """Schema de resposta de KPI"""
    category: str
    score: float
    total_responses: int
    trend: str


class RecommendationResponse(BaseModel):
    """Schema de recomendação"""
    id: int
    recommendation_text: str
    priority: str
    category: str
    score: float
    
    class Config:
        from_attributes = True


class SurveyResultsAnalysis(BaseModel):
    """Schema completo de análise de pesquisa"""
    survey_id: int
    survey_title: str
    total_responses: int
    average_score: float
    kpis: List[KPIResponse]
    recommendations: List[RecommendationResponse]
    status: str  # "excellent", "good", "needs_improvement"
