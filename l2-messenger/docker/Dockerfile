FROM python:3.12-slim
WORKDIR /app

# Instala solo binarios (falla si no hay wheel y así evitas compilar)
RUN pip install --no-cache-dir --only-binary=:all: cryptography

COPY src ./src
ENV PYTHONPATH=/app/src
CMD ["python","-m","l2msg.cli"]
