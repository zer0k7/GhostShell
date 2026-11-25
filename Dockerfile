FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# SSH honeypot 2222, dashboard 5000, fake admin panel 8081
EXPOSE 2222 5000 8081
VOLUME ["/app/data"]

CMD ["python", "run.py"]
