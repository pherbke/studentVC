# Stage 1: Build stage
FROM python:3.11.4-slim AS builder

# Install dependencies for building
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && curl https://sh.rustup.rs -sSf | sh -s -- -y \
    && rm -rf /var/lib/apt/lists/*

# Add .cargo/bin to PATH
ENV PATH="/root/.cargo/bin:${PATH}"

# Build bbs-core
COPY bbs-core/ /bbs-core/
WORKDIR /bbs-core/python
RUN chmod +x build.sh && ./build.sh

# Stage 2: Final image
FROM python:3.11.4-slim

# Install runtime dependencies
# RUN apt-get update && apt-get install -y --no-install-recommends \
#     libgomp1 \
#     && rm -rf /var/lib/apt/lists/*

# Copy compiled bbs-core from builder stage
COPY --from=builder /bbs-core /bbs-core

# Copy application files
WORKDIR /
COPY backend/requirements.txt /
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/main.py /
COPY backend/gunicorn.conf.py /
COPY backend/src/ /src/

# Run the Python service
ENTRYPOINT ["python", "main.py"]
# ENTRYPOINT ["gunicorn", "-c" ,"gunicorn.conf.py", "main:app", "-b 0.0.0.0:80"]
