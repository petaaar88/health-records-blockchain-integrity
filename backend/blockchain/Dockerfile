FROM python:3.12-slim
WORKDIR /app

COPY ./requirements.txt .
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

COPY ./blockchain .

RUN mkdir -p /app/blockchain/db

ENV PYTHONUNBUFFERED=1

CMD ["python", "run.py", "5001"]
