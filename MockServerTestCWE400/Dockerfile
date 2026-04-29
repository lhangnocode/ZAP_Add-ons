FROM python:3.9-slim

WORKDIR /app

# Khởi tạo và cài đặt dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

EXPOSE 8080

CMD ["gunicorn", "--workers", "10", "--bind", "0.0.0.0:8080", "app:app"]
