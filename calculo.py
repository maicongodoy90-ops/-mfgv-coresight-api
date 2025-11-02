from typing import List, Dict
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

class RespostaDiagnostico(BaseModel):
    respostas: List[int]  # Exemplo: [8, 6, 9, 7, 8]

@router.post("/calculo/diagnostico")
def calcular_score(item: RespostaDiagnostico) -> Dict:
    respostas = item.respostas
    media = sum(respostas) / len(respostas) if respostas else 0
    benchmark = 7.0
    if media >= benchmark:
        nivel = "Excelente"
    elif media >= 5:
        nivel = "Bom, mas precisa evoluir"
    else:
        nivel = "Crítico - atenção urgente"
    return {
        "media": round(media, 2),
        "respostas_enviadas": respostas,
        "interpretacao": nivel,
        "benchmark": benchmark
    }
