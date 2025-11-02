from models import (
    Base, engine, User, Survey, SurveyQuestion, 
    SurveyResponse, SurveyAnswer, get_db
)
from sqlalchemy.orm import Session
from datetime import datetime
import sys

# Criar tabelas
Base.metadata.create_all(bind=engine)

# Conectar ao banco
db = Session(bind=engine)

try:
    # Limpar dados anteriores
    db.query(SurveyAnswer).delete()
    db.query(SurveyResponse).delete()
    db.query(SurveyQuestion).delete()
    db.query(Survey).delete()
    db.query(User).delete()
    db.commit()
    
    print("✅ Banco limpo")
    
    # 1. Criar usuário teste
    user = User(
        username="admin",
        email="admin@test.com",
        full_name="Admin Teste",
        hashed_password="hashed_pwd_123"
    )
    db.add(user)
    db.commit()
    print("✅ Usuário criado")
    
    # 2. Criar pesquisa
    survey = Survey(
        title="Diagnóstico Clima Organizacional 2025",
        description="Pesquisa para avaliar engajamento da equipe",
        status="ativa",
        created_by_id=user.id
    )
    db.add(survey)
    db.commit()
    print("✅ Pesquisa criada")
    
    # 3. Criar perguntas
    questions = [
        SurveyQuestion(survey_id=survey.id, question_text="Como avalia seu engajamento?", order=1),
        SurveyQuestion(survey_id=survey.id, question_text="Sente-se reconhecido?", order=2),
        SurveyQuestion(survey_id=survey.id, question_text="Confia na liderança?", order=3),
    ]
    db.add_all(questions)
    db.commit()
    print("✅ Perguntas criadas")
    
    # 4. Criar respostas (5 colaboradores responderam)
    for i in range(1, 6):
        response = SurveyResponse(
            survey_id=survey.id,
            user_id=user.id
        )
        db.add(response)
        db.flush()  # Gera o ID
        
        # Adicionar respostas para cada pergunta
        answers = [
            SurveyAnswer(response_id=response.id, question_id=questions[0].id, answer_value=7),
            SurveyAnswer(response_id=response.id, question_id=questions[1].id, answer_value=6),
            SurveyAnswer(response_id=response.id, question_id=questions[2].id, answer_value=8),
        ]
        db.add_all(answers)
    
    db.commit()
    print("✅ Respostas criadas (5 colaboradores)")
    print("\n✅✅✅ BANCO POPULADO COM SUCESSO! ✅✅✅")
    
except Exception as e:
    print(f"❌ Erro: {e}")
    db.rollback()
    sys.exit(1)

finally:
    db.close()
