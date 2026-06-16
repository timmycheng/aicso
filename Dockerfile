FROM python:3.11-slim

ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

ENV HTTP_PROXY=${HTTP_PROXY}
ENV HTTPS_PROXY=${HTTPS_PROXY}
ENV NO_PROXY=${NO_PROXY}

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

# Install Python dependencies
RUN pip install --no-cache-dir -e .

# Copy config, playbooks and skills
COPY config.yaml.example config.yaml
COPY playbooks/ playbooks/
COPY skills/ skills/

# Create data directories
RUN mkdir -p data/chromadb

# Clean up proxy settings from final image
ENV HTTP_PROXY=
ENV HTTPS_PROXY=
ENV NO_PROXY=

# Expose web port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/')" || exit 1

# Start web server
CMD ["aicso-web"]
