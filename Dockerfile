# Escolhe a imagem base do Python leve e recente
FROM python:3.10-slim

# Define o diretório de trabalho dentro do container
WORKDIR /app

# Copia o arquivo de dependências para dentro do container
COPY requirements.txt .

# Instala todas as dependências declaradas no requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copia todos os arquivos e pastas do projeto para dentro do container
COPY . .

# Comando para iniciar sua API quando o container ligar
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]
