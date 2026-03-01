FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/
COPY examples/ examples/

RUN pip install --no-cache-dir .

EXPOSE 8000

# Default: run the Mock Server
CMD ["uvicorn", "aaa.env.mock_server:app", "--host", "0.0.0.0", "--port", "8000"]
