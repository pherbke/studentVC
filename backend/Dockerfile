# Stage 1: Build stage with optimized Rust building
FROM python:3.11.4-slim AS builder

# Install dependencies for building with caching optimizations
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    pkg-config \
    libssl-dev \
    && curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain stable \
    && rm -rf /var/lib/apt/lists/*

# Add .cargo/bin to PATH and optimize Rust builds
ENV PATH="/root/.cargo/bin:${PATH}"
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

# Build bbs-core with optimization
COPY bbs-core/ /bbs-core/
WORKDIR /bbs-core/python
RUN chmod +x build.sh && ./build.sh

# Stage 2: Production runtime image
FROM python:3.11.4-slim

# Create non-root user for security
RUN groupadd -r app && useradd -r -g app app

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Set working directory
WORKDIR /app

# Copy requirements first for better layer caching
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip cache purge

# Copy compiled bbs-core from builder stage
COPY --from=builder /bbs-core /app/bbs-core

# Copy application files
COPY backend/main.py ./
COPY backend/gunicorn.conf.py ./
COPY backend/src/ ./src/

# Create instance directory with proper permissions
RUN mkdir -p /app/instance && chown -R app:app /app

# Switch to non-root user
USER app

# Set environment variables for production
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:8080/health', timeout=5)" || exit 1

# Expose port
EXPOSE 8080

# Use gunicorn for production with optimized settings
ENTRYPOINT ["gunicorn", "-c", "gunicorn.conf.py", "main:app"]
