# Usa Python slim per avere meno peso
FROM python:3.11-slim

# Imposta la cartella di lavoro
WORKDIR /app

# Copia e installa le dipendenze
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia tutto il resto del progetto
COPY . .

# Esponi la porta usata da Streamlit
EXPOSE 8000

# Comando per avviare Streamlit
CMD ["streamlit", "run", "app.py", "--server.port", "8000", "--server.address", "0.0.0.0"]
