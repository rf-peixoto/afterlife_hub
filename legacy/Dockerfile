FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .
COPY client.py .
COPY README.md .
COPY LICENSE .

RUN useradd -r -u 10001 -m afterlife \
    && mkdir -p /data \
    && chown -R afterlife:afterlife /app /data

USER afterlife

EXPOSE 2077

CMD ["python", "server.py", "--host", "0.0.0.0", "--port", "2077"]