FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install dependencies
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy source code and reference data files
COPY OWASP_Application_Security_Verification_Standard_5.0.0_en.json Tinyfah.json /app/
COPY backend /app/backend

# Create screenshots directory
RUN mkdir -p /app/backend/screenshots

EXPOSE 8000

ENV PORT=8000
CMD ["sh", "-c", "uvicorn main:app --app-dir backend --host 0.0.0.0 --port ${PORT}"]
