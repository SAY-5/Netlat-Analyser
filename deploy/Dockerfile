FROM python:3.12-slim

LABEL maintainer="netlat" \
      description="Network Latency Analyzer & Packet Debugger"

# Install system dependencies: tcpdump for capture, iproute2 for network tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tcpdump \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user (but we'll run as root for NET_RAW capability)
WORKDIR /app

# Copy and install the package
COPY . /app/
RUN pip install --no-cache-dir .

# Create capture output directory
RUN mkdir -p /captures

# Expose Prometheus metrics port
EXPOSE 9090

# Default entrypoint
ENTRYPOINT ["netlat"]
CMD ["capture", "--interface=any", "--duration=3600", "--output-dir=/captures"]
