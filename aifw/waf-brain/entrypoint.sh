#!/bin/bash

# ── Flush existing rules ─────────────────────────────────────
iptables -t nat -F 2>/dev/null || true
iptables -F FORWARD 2>/dev/null || true

# ── FORWARD: allow all forwarded traffic ─────────────────────
iptables -P FORWARD ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -j ACCEPT

# ── MASQUERADE: for return traffic ───────────────────────────
iptables -t nat -A POSTROUTING -j MASQUERADE

# ── Create AIFW chain for dynamic rules ──────────────────────
iptables -t nat -N AIFW_INTERCEPT 2>/dev/null || iptables -t nat -F AIFW_INTERCEPT
iptables -t nat -A PREROUTING -j AIFW_INTERCEPT

echo "[AIFW] iptables gateway rules configured"

# Start Nginx in the background
nginx

# The BLOCKING_MODE environment variable should be passed from docker-compose
if [ "$MODSEC_RULE_ENGINE" = "On" ]; then
    BLOCK_ARG="--blocking-mode"
else
    BLOCK_ARG=""
fi

# We don't need access log since we write our own custom JSON log file in end_points_waf.py
python3 -m waf_brain -l 127.0.0.1 -p 8000 $BLOCK_ARG
