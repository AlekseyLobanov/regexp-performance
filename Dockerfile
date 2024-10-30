FROM python:3.12.7-slim

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

WORKDIR /app

RUN apt-get update && apt-get install -y build-essential git libre2-dev pkg-config

COPY requirements.txt .
RUN pip install -U pip && pip install -r requirements.txt

COPY war-and-peace.txt.gz .
COPY pitayasmoothie-dark.mplstyle .
COPY measure_performance.py .
