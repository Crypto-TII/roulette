FROM python:3.8.10-slim

WORKDIR /solver

COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY source .

CMD [ "python", "./main.py" ]