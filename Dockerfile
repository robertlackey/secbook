FROM python:3.8-alpine

RUN apk update && \
    apk add --no-cache gcc pkgconfig libpq && \
    apk add --no-cache build-base python3-dev swig && \
    adduser -D appuser

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && \
    rm -rf /root/.cache

COPY . /app
RUN chown -R appuser:appuser /app
USER appuser
