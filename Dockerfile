# Используем легковесный официальный образ Python 3.11
FROM python:3.11-slim

# Отключаем создание pyc файлов и буферизацию вывода (полезно для логов)
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Устанавливаем системные зависимости для YARA, ssdeep, магии файлов и DIE
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libmagic1 \
    libfuzzy-dev \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Установка Detect It Easy (CLI-версия - diec)
# Загружаем актуальный релиз для Linux
RUN wget https://github.com/horsicq/Detect-It-Easy/releases/download/3.09/die_lin64_portable_3.09.zip -O /tmp/die.zip && \
    unzip /tmp/die.zip -d /opt/die && \
    ln -s /opt/die/diec /usr/local/bin/diec && \
    rm /tmp/die.zip

# Создаем директории для приложения и для семплов
WORKDIR /app
RUN mkdir -p /samples

# Устанавливаем Python-зависимости (FastAPI, инструменты анализа)
# Используем requirements.txt для кэширования слоев
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем исходный код воркера (создадим на Phase 2)
COPY ./worker /app/worker

# Создаем пользователя без прав root (требование ТЗ 5. Security)
RUN useradd -m -s /bin/bash jumal_user && \
    chown -R jumal_user:jumal_user /app /samples

# Переключаемся на безопасного пользователя
USER jumal_user

# Открываем порт для FastAPI
EXPOSE 8000

# Запуск FastAPI сервера через Uvicorn
CMD ["uvicorn", "worker.main:app", "--host", "0.0.0.0", "--port", "8000"]
