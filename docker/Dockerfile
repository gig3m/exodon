FROM python:3.12-slim-bookworm
RUN pip install --no-cache-dir httpx==0.28.1
# The repo is bind-mounted read-only at /app; only var/ is writable.
WORKDIR /app
USER 1000:1000
ENV PYTHONUNBUFFERED=1
CMD ["python3", "src/shadow.py", "run"]
