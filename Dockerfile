# syntax=docker/dockerfile:1

# Build stage
FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016 AS builder

# Set working directory
WORKDIR /app

# The build context itself must match the frozen source identity.
COPY . .
RUN python tools/generate_release_manifests.py --check && \
    test -f requirements-runtime.lock

# Install build dependencies only after source and lock admission.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
    && rm -rf /var/lib/apt/lists/*

# A release runtime requires a fully hashed runtime lock. The CI lock only
# qualifies the narrower security/statistical toolchain.
RUN python -m venv /opt/venv && \
    . /opt/venv/bin/activate && \
    pip install --no-cache-dir --require-hashes -r requirements-runtime.lock && \
    pip install --no-deps -e .

# Runtime stage
FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        unzip \
        bubblewrap \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 aide

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
# Copy the package files needed for the installation
COPY --from=builder /app /app
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Create and set permissions for logs and workspaces
RUN mkdir -p logs workspaces && \
    chown -R aide:aide /app

# Switch to non-root user
USER aide

# Set default command
ENTRYPOINT ["aide-rsi"]
