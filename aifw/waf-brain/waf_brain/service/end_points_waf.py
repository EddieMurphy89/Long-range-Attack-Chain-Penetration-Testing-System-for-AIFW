import aiofiles
import aiohttp
import logging

from sanic import response, Blueprint

from waf_brain.inferring import process_payload

log = logging.getLogger("waf-brain")

waf_blueprint = Blueprint("waf_brain")


@waf_blueprint.route('/<path:[\w\W\/]*>',
                     methods=[
                         "GET",
                         "POST",
                         "PUT",
                         "DELETE",
                         "HEAD",
                         "OPTIONS"
                     ])
async def waf(request, path):
    MODEL = request.app.config["MODEL"]
    PROTECTED_URL = request.app.config["PROTECTED_URL"]
    BLOCKING_MODE = request.app.config["BLOCKING_MODE"]
    BLOCKING_THRESHOLD = request.app.config["BLOCKING_THRESHOLD"]
    TIMEOUT_BACKEND = request.app.config["TIMEOUT_BACKEND"]

    total = []
    
    def add_payload(arg_name, arg_val):
        if not arg_val: return
        import string
        clean_val = "".join(c for c in str(arg_val) if c in string.printable)
        if len(clean_val) < 2: return
        res = process_payload(MODEL, arg_name, [clean_val], False)
        if res:
            total.append(res)

    # 1. Query parameters
    for arg, val_list in request.args.items():
        val = val_list[0] if isinstance(val_list, list) and val_list else val_list
        add_payload(f"GET:{arg}", val)
            
    # 2. Form parameters
    if request.form:
        for arg, val_list in request.form.items():
            val = val_list[0] if isinstance(val_list, list) and val_list else val_list
            add_payload(f"POST:{arg}", val)
    # 3. Raw Body (if not parsed as form)
    elif request.body:
        add_payload("BODY", request.body.decode("utf-8", errors="ignore"))
        
    # 4. URI Path itself
    if path:
        add_payload("URI_PATH", path)

    #
    # Request must be block if the WAF detect and attack?
    #
    if BLOCKING_MODE:
        if any(x["score"] >= BLOCKING_THRESHOLD for x in total):
            target_ip_port = request.headers.get("x-aifw-original-target")
            import json
            import datetime
            try:
                with open("/var/log/waf-brain.log", "a") as f:
                    log_entry = {
                        "timestamp": datetime.datetime.now().isoformat(),
                        "client_ip": request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for", "").split(",")[0].strip() or request.ip,
                        "target": target_ip_port or PROTECTED_URL,
                        "request_method": request.method,
                        "request_uri": ("/" + path) if path else "/",
                        "status_code": 403,
                        "scores": total,
                        "blocked": True
                    }
                    f.write(json.dumps(log_entry) + "\n")
            except Exception as e:
                pass
            return response.text("Dangerous request detected and blocked",
                                 status=403)


    target_ip_port = request.headers.get("x-aifw-original-target")
    if target_ip_port:
        target_url = f"http://{target_ip_port}/{path}"
    else:
        target_url = f"{PROTECTED_URL}/{path}" if path else PROTECTED_URL

    async with aiohttp.ClientSession(cookies=request.cookies,
                                     read_timeout=TIMEOUT_BACKEND) as session:

        try:
            async with session.request(
                    request.method,
                    target_url,
                    headers=request.headers,
                    data=request.body,
                    params=request.args) as resp:

                body = await resp.read()
                
                # Write log
                import json
                import datetime
                try:
                    with open("/var/log/waf-brain.log", "a") as f:
                        log_entry = {
                            "timestamp": datetime.datetime.now().isoformat(),
                            "client_ip": request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for", "").split(",")[0].strip() or request.ip,
                            "target": target_ip_port or PROTECTED_URL,
                            "request_method": request.method,
                            "request_uri": "/" + path if path else "/",
                            "status_code": resp.status,
                            "scores": total,
                            "blocked": False # We'll update this if we block
                        }
                        f.write(json.dumps(log_entry) + "\n")
                except Exception as e:
                    print(f"Error writing log: {e}", flush=True)

                return response.raw(
                    body=body,
                    status=resp.status,
                    headers=dict(resp.headers),
                    content_type=resp.content_type
                )
        except Exception as e:
            return response.text(f"Proxy Error: {str(e)}", status=502)


__all__ = ("waf_blueprint", )
