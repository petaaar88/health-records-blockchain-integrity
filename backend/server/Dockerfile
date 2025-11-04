FROM python:3.12-slim
WORKDIR /app

# Copy dependencies
COPY ./requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ./server ./server
COPY ./blockchain ./blockchain

ENV PYTHONPATH=/app

WORKDIR /app/server
EXPOSE 5000

CMD ["python", "server.py"]
