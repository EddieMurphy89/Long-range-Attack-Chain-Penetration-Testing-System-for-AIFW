import httpx
import json
import datetime
import os
import urllib.parse
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from request import Request as WafRequest
from classifier import ThreatClassifier

app = FastAPI()

# Initialize classifier
threat_clf = ThreatClassifier()

PROTECTED_URL = os.environ.get("PROTECTED_URL", "http://localhost:80")
BLOCKING_MODE = os.environ.get("MODSEC_RULE_ENGINE", "DetectionOnly") == "On"

client = httpx.AsyncClient(timeout=30.0)

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"])
async def proxy_and_classify(request: Request, path: str):
    # 1. Reconstruct logical request for the ThreatClassifier
    req_obj = WafRequest()
    req_obj.origin = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for", "").split(",")[0].strip() or getattr(request.client, "host", "127.0.0.1")
    req_obj.host = request.headers.get("host", "")
    req_obj.request = "/" + path if path else "/"
    req_obj.method = request.method
    req_obj.headers = dict(request.headers)
    req_obj.threat_type = 'None'
    
    # Read body
    req_body = await request.body()
    if req_body:
        req_obj.body = req_body.decode("utf-8", errors="ignore")
    else:
        req_obj.body = ""

    # 2. Run Classification
    # The classifier expects populated req_obj.threats dict
    try:
        threat_clf.classify_request(req_obj)
    except Exception as e:
        print(f"Classification error: {e}", flush=True)
        if not hasattr(req_obj, "threats"):
            req_obj.threats = {}

    # Extract threats (skip 'valid')
    detected_threats = [
        {"threat": threat, "location": loc} 
        for threat, loc in req_obj.threats.items() 
        if threat != 'valid'
    ]
    is_attack = len(detected_threats) > 0

    target_ip_port = request.headers.get("x-aifw-original-target")
    
    # 3. Block if On
    if BLOCKING_MODE and is_attack:
        log_request(
            client_ip=req_obj.origin,
            target=target_ip_port or PROTECTED_URL,
            method=req_obj.method,
            uri=req_obj.request,
            status=403,
            threats=detected_threats,
            blocked=True
        )
        return JSONResponse(status_code=403, content={"error": "Dangerous request detected and blocked"})

    # 4. Proxy to backend
    if target_ip_port:
        target_url = f"http://{target_ip_port}/{path}"
    else:
        target_url = f"{PROTECTED_URL}/{path}" if path else PROTECTED_URL

    try:
        backend_response = await client.request(
            method=request.method,
            url=target_url,
            headers={k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")},
            params=request.query_params,
            content=req_body,
            cookies=request.cookies
        )
        
        log_request(
            client_ip=req_obj.origin,
            target=target_ip_port or PROTECTED_URL,
            method=req_obj.method,
            uri=req_obj.request,
            status=backend_response.status_code,
            threats=detected_threats,
            blocked=False
        )

        return Response(
            content=backend_response.content,
            status_code=backend_response.status_code,
            headers={k: v for k, v in backend_response.headers.items() if k.lower() not in ("content-encoding", "content-length", "transfer-encoding")}
        )
    except Exception as e:
        print(f"Proxy error: {e}", flush=True)
        return JSONResponse(status_code=502, content={"error": "Bad Gateway"})

def log_request(client_ip, target, method, uri, status, threats, blocked):
    log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "client_ip": client_ip,
        "target": target,
        "request_method": method,
        "request_uri": uri,
        "status_code": status,
        # Format threats like waf-brain scores for dashboard compatibility
        "scores": [{"paramName": t["location"], "score": 1, "weights": [{"letter": t["threat"], "weight": 1.0}]} for t in threats],
        "blocked": blocked
    }
    try:
        with open("/var/log/ml-based-waf.log", "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"Log write error: {e}", flush=True)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
