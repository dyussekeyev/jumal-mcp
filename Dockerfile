# Use lightweight official Python 3.11 image
FROM python:3.11-slim

# Disable .pyc file creation and output buffering (useful for logs)
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies for YARA, ssdeep, file magic, DIE, and FLOSS
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libmagic1 \
    libfuzzy-dev \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Detect It Easy (CLI version - diec)
# Download the current release for Linux
RUN wget https://github.com/horsicq/Detect-It-Easy/releases/download/3.09/die_lin64_portable_3.09.zip -O /tmp/die.zip && \
    unzip /tmp/die.zip -d /opt/die && \
    ln -s /opt/die/diec /usr/local/bin/diec && \
    rm /tmp/die.zip

# Create directories for the application and samples
WORKDIR /app
RUN mkdir -p /samples

# Install Python dependencies (FastAPI, analysis tools)
# Using requirements.txt for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy worker source code
COPY ./worker /app/worker

# Create non-root user (requirement from spec section 5. Security)
RUN useradd -m -s /bin/bash jumal_user && \
    chown -R jumal_user:jumal_user /app /samples

# Switch to safe user
USER jumal_user

# Expose port for FastAPI
EXPOSE 8000

# Start FastAPI server via Uvicorn
CMD ["uvicorn", "worker.main:app", "--host", "0.0.0.0", "--port", "8000"]
