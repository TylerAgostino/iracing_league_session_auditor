FROM python:3.12-slim AS builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Copy application code
COPY . .

# Create directory for state file
RUN mkdir -p /data && \
    chmod -R 777 /data

# Install the package in the runtime image
RUN pip install --no-cache-dir --no-warn-script-location -e .

FROM python:3.12-slim AS runtime
WORKDIR /app
COPY --from=builder /app /app
COPY --from=builder /data /data
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages

VOLUME ["/data"]

# Set the entrypoint to use the CLI command defined in pyproject.toml
ENTRYPOINT ["python", "-m", "iracing_league_session_auditor"]

# Default command if no arguments are provided
CMD ["--help"]
