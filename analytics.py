from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from models import get_db, Survey, SurveyResponse, SurveyAnswer, SurveyQuestion
from typing import List, Dict
import statistics

router = APIRouter()

# ================= ANALYTICS ENDPOINTS =================

@router.get("/api/analytics/survey/{survey_id}")
def analisar_survey(survey_id: int, db: Session = Depends(get_db)):
    """
    Analisa uma pesquisa e retorna scores agregados.
    """
    survey = db.query(Survey).filter(Survey.id == survey_id).first()
    if not survey:
        raise HTTPException(status_code=404, detail="Pesquisa não encontrada")
    
    # Busca todas as respostas dessa pesquisa
    respostas = db.query(SurveyResponse).filter(SurveyResponse.survey_id == survey_id).all()
    
    if not respostas:
        return {"msg": "Nenhuma resposta coletada ainda", "survey_id": survey_id}
    
    # Calcula scores agregados
    scores_por_pergunta = {}
    for resposta in respostas:
        for answer in resposta.answers:
            pergunta_id = answer.question_id
            if pergunta_id not in scores_por_pergunta:
                scores_por_pergunta[pergunta_id] = []
            
            if answer.answer_value:
                scores_por_pergunta[pergunta_id].append(answer.answer_value)
    
    # Calcula média por pergunta
    media_scores = {}
    for pergunta_id, valores in scores_por_pergunta.items():
        media_scores[pergunta_id] = {
            "media": round(statistics.mean(valores), 2),
            "desvio": round(statistics.stdev(valores), 2) if len(valores) > 1 else 0,
            "total_respostas": len(valores),
            "minimo": min(valores),
            "maximo": max(valores)
        }
    
    return {
        "survey_id": survey_id,
        "total_respostas": len(respostas),
        "scores_por_pergunta": media_scores
    }


@router.get("/api/analytics/summary/{survey_id}")
def resumo_survey(survey_id: int, db: Session = Depends(get_db)):
    """
    Retorna um resumo executivo da pesquisa.
    """
    survey = db.query(Survey).filter(Survey.id == survey_id).first()
    if not survey:
        raise HTTPException(status_code=404, detail="Pesquisa não encontrada")
    
    respostas = db.query(SurveyResponse).filter(SurveyResponse.survey_id == survey_id).all()
    
    if not respostas:
        return {"msg": "Sem dados para resumo"}
    
    # Coleta todos os valores numéricos
    todos_valores = []
    for resposta in respostas:
        for answer in resposta.answers:
            if answer.answer_value:
                todos_valores.append(answer.answer_value)
    
    if not todos_valores:
        return {"msg": "Sem respostas numéricas"}
    
    media_geral = statistics.mean(todos_valores)
    
    # Classifica o nível
    if media_geral >= 8:
        nivel = "Excelente"
    elif media_geral >= 6:
        nivel = "Bom"
    elif media_geral >= 4:
        nivel = "Regular"
    else:
        nivel = "Crítico"
    
    return {
        "survey_id": survey_id,
        "total_respostas": len(respostas),
        "score_medio_geral": round(media_geral, 2),
        "nivel": nivel,
        "recomendacao": f"Score {media_geral:.1f}/10 - {nivel}"
    }
