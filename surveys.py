from fastapi import APIRouter
from typing import List, Dict

router = APIRouter()

@router.get("/api/surveys/questions")
def listar_perguntas():
    # Exemplo didático — coloque as perguntas reais do seu Excel!
    return [
        "Qual o porte da sua empresa?",
        "Principais objetivos estratégicos?",
        "Como avalia o engajamento?",
        "... (outras perguntas)"
    ]

@router.post("/api/surveys/submit")
def enviar_resposta(resposta: Dict):
    # Aqui você pode salvar as respostas (futuramente no banco)
    return {"msg": "Resposta recebida!", "resposta": resposta}
