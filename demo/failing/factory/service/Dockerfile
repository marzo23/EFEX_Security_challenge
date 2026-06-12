# VULN-006 -- using a floating tag (no SHA pin); Trivy & Checkov flag this
FROM python:3.11

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# VULN-007 -- no USER directive; container runs as root
# (Checkov CKV_DOCKER_3 + custom check EFEX_DOCKER_001 in policies/checkov/)

EXPOSE 8000

# VULN-008 -- no HEALTHCHECK (Checkov CKV_DOCKER_2)

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
