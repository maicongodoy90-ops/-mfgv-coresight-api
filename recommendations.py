from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from db import get_db
from models import Survey, SurveyResponse, SurveyAnswer
import statistics
import json

router = APIRouter()

@router.post("/api/recommendations/generate/{survey_id}")
def gerar_recomendacoes(survey_id: int, db: Session = Depends(get_db)):
    """
    Gera recomendações baseadas em dados do survey (sem API externa).
    Você completa as recomendações manualmente via Perplexity Labs.
    """
    
    # 1. Buscar survey
    survey = db.query(Survey).filter(Survey.id == survey_id).first()
    if not survey:
        raise HTTPException(status_code=404, detail="Pesquisa não encontrada")
    
    respostas = db.query(SurveyResponse).filter(SurveyResponse.survey_id == survey_id).all()
    if not respostas:
        return {"msg": "Sem dados para gerar recomendações"}
    
    # 2. Calcular scores
    scores_por_pergunta = {}
    for resposta in respostas:
        for answer in resposta.answers:
            if answer.question_id not in scores_por_pergunta:
                scores_por_pergunta[answer.question_id] = []
            if answer.answer_value:
                scores_por_pergunta[answer.question_id].append(answer.answer_value)
    
    # 3. Preparar relatório
    medias = {qid: statistics.mean(vals) for qid, vals in scores_por_pergunta.items()}
    media_geral = statistics.mean(list(medias.values()))
    
    # Classificar problemas
    problemas = []
    for pergunta in survey.questions:
        media = medias.get(pergunta.id, 0)
        if media < 5:
            problemas.append({
                "pergunta": pergunta.question_text,
                "score": round(media, 2),
                "severidade": "CRÍTICO"
            })
        elif media < 6.5:
            problemas.append({
                "pergunta": pergunta.question_text,
                "score": round(media, 2),
                "severidade": "ATENÇÃO"
            })
    
    # 4. Gerar prompt para você usar no Perplexity Labs
    prompt_para_perplexity = f"""
    Análise de Clima Organizacional - Diagnóstico Inteligente

    DADOS COLETADOS:
    - Total de respondentes: {len(respostas)}
    - Score médio geral: {round(media_geral, 2)}/10
    
    SCORES POR DIMENSÃO:
    {chr(10).join([f"- {q.question_text}: {round(medias.get(q.id, 0), 2)}/10" for q in survey.questions])}
    
    PROBLEMAS IDENTIFICADOS:
    {chr(10).join([f"- [{p['severidade']}] {p['pergunta']} (score: {p['score']})" for p in problemas])}
    
    TAREFA:
    Com base nestes dados, gere 3 recomendações estratégicas estruturadas com:
    1. Título da ação
    2. Descrição (2-3 linhas)
    3. ROI estimado (€€€/€€/€)
    4. Prazo (semanas)
    5. Responsável (RH/CEO/Gestor)
    
    Use as 37 áreas do MFGV CoreSight como referência.
    """
    
    return {
        "survey_id": survey_id,
        "status": "Dados processados com sucesso",
        "score_medio_geral": round(media_geral, 2),
        "total_respondentes": len(respostas),
        "problemas_identificados": len(problemas),
        "detalhes": {
            "scores": {q.question_text: round(medias.get(q.id, 0), 2) for q in survey.questions},
            "problemas": problemas
        },
        "prompt_perplexity": prompt_para_perplexity,
        "instruções": "Copie o 'prompt_perplexity' e cole em Perplexity Labs para gerar recomendações com IA"
    }
