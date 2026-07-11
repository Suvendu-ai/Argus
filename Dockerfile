# ─────────────────────────────────────────
# ARGUS — Python API Dockerfile
# ─────────────────────────────────────────
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies for Scapy
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --timeout=300 -r requirements.txt

# Copy entire project
COPY . .

# Create necessary directories
RUN mkdir -p reports alerts data/raw data/processed ml/models

# Expose API port
EXPOSE 8000

# Start FastAPI server
CMD ["python", "-m", "api.main"]