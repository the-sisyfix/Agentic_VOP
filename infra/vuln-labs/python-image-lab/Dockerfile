# Intentionally outdated Python runtime with vulnerable dependencies
FROM python:3.8-slim-buster

# Install vulnerable pip packages directly into the image
RUN pip install --no-cache-dir \
    flask==2.0.0 \
    jinja2==3.0.0 \
    requests==2.25.0 \
    cryptography==3.3.2 \
    pyyaml==5.3.1 \
    urllib3==1.26.4 \
    werkzeug==2.0.0 \
    setuptools==58.0.0 \
    pillow==8.1.0 \
    certifi==2020.12.5

# Add a placeholder app
RUN mkdir -p /app
RUN echo 'from flask import Flask; app = Flask(__name__)' > /app/main.py

# VULN: Running as root (no USER instruction)
# VULN: No HEALTHCHECK defined
WORKDIR /app
EXPOSE 5000
CMD ["python", "main.py"]
