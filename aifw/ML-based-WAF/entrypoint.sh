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

# Start Nginx background proxy
nginx

# Start ML-based-WAF proxy
echo "[AIFW] Starting ML-based-WAF proxy process..."
python proxy.py
