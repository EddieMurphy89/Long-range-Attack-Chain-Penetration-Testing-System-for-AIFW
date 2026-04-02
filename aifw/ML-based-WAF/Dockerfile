FROM python:3.8-slim

# Install system dependencies (nginx, iptables)
RUN apt-get update && apt-get install -y \
    nginx \
    iptables \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirement files first
COPY requirements.txt ./
# Override old scikit-learn dependency to avoid compilation errors on modern systems if possible,
# But we'll try to stick to the repo's requirements as closely as possible.
# Add fastapi, uvicorn, and httpx for our new proxy.
RUN pip install -U pip && \
    pip install -r requirements.txt && \
    pip install fastapi uvicorn httpx

# Copy ML-based-WAF contents
COPY . /app/

# create nginx overriding config
RUN rm /etc/nginx/sites-enabled/default || true && \
    rm /etc/nginx/conf.d/default.conf || true
COPY WAF/nginx.conf /etc/nginx/conf.d/aifw.conf

# Log preparation
RUN touch /var/log/ml-based-waf.log && chmod 666 /var/log/ml-based-waf.log

# Ensure entrypoint is executable
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# cd to WAF directory since classifier loads relative path "../Classifier/..."
WORKDIR /app/WAF

ENTRYPOINT ["/entrypoint.sh"]
