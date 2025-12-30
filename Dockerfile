# Use Python slim image
FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

# Install SSH client (handy for debugging) and ca-certs
RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-client ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ssh_mcp_server.py .

# Non-root user
RUN useradd -m -u 1000 mcpuser && \
    mkdir -p /home/mcpuser/.ssh && \
    chown -R mcpuser:mcpuser /app /home/mcpuser/.ssh

USER mcpuser

CMD ["python", "ssh_mcp_server.py"]
