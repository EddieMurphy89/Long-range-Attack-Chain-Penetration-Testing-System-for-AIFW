FROM owasp/modsecurity-crs:nginx

USER root

ENV TZ=Asia/Shanghai

# Install iptables (required for transparent traffic interception via NAT)
# Install tzdata for timezone configuration
RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends iptables tzdata && \
    ln -fs /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata && \
    rm -rf /var/lib/apt/lists/*

# Copy custom Nginx site config
COPY nginx-default.conf /etc/nginx/conf.d/aifw.conf

# Copy ModSecurity override (DetectionOnly + JSON audit log)
COPY modsec-override.conf /etc/modsecurity.d/owasp-crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf


# Ensure log directory exists
RUN mkdir -p /var/log/modsecurity && \
    touch /var/log/modsecurity/audit.log && \
    chown -R nginx:nginx /var/log/modsecurity

# Create entrypoint script that substitutes env vars in nginx config
COPY docker-entrypoint-custom.sh /docker-entrypoint-custom.sh
RUN chmod +x /docker-entrypoint-custom.sh

EXPOSE 80

ENTRYPOINT ["/docker-entrypoint-custom.sh"]
CMD ["nginx", "-g", "daemon off;"]
