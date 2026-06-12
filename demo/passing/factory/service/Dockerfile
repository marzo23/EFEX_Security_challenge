# VULN-006 remediated -- base image is the explicit `-slim` channel.
# In production the deploy pipeline resolves the immutable digest with
# `docker buildx imagetools inspect python:3.11-slim` and rewrites this
# line to `python:3.11-slim@sha256:<digest>` before the build. We keep
# the tag-only form in the demo so the Green image is reproducibly
# buildable; a hand-pinned all-zeros placeholder used to live here and
# made the demo image unbuildable (VERIFICATION 4.3-8).
FROM python:3.11-slim

# VULN-007 remediated -- create a non-root user before installing anything
# that would otherwise be owned by root.
RUN groupadd --system --gid 10001 appgroup \
    && useradd --system --uid 10001 --gid appgroup --shell /sbin/nologin appuser

WORKDIR /app

COPY --chown=appuser:appgroup requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appgroup app/ ./app/

# VULN-007 remediated -- drop to non-root for the runtime stage.
USER appuser

EXPOSE 8000

# VULN-008 remediated -- basic liveness check.
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health',timeout=2).status==200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
