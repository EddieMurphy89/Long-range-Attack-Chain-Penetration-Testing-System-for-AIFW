FROM tensorflow/tensorflow:nightly-py3

# Install nginx
RUN apt-get update && apt-get install -y nginx iptables iproute2 && rm -rf /var/lib/apt/lists/*

RUN pip install -U pip
COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

COPY . /app
WORKDIR /app

# remove default nginx config
RUN rm /etc/nginx/sites-enabled/default || true
RUN rm /etc/nginx/conf.d/default.conf || true

# Prepare log file
RUN touch /var/log/waf-brain.log && chmod 666 /var/log/waf-brain.log

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
