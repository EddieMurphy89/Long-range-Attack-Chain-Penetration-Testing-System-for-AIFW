import subprocess
import pprint

def run(cmd):
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return res.stdout.strip()

print("1. Attacker IP (a6422344e713):")
print(run("docker inspect -f '{{.NetworkSettings.Networks.vulhub_net_dmz_a.IPAddress}}' a6422344e713"))

print("2. Target IP (3ee4a5d19372):")
print(run("docker inspect -f '{{.NetworkSettings.Networks.vulhub_net_dmz_a.IPAddress}}' 3ee4a5d19372"))

print("3. Try curl from attacker to target:")
print(run("docker run --rm --network container:a6422344e713 curlimages/curl -v http://192.168.6.3:7860/"))

print("4. Try proxy directly from Host to ML-WAF (127.0.0.1:10001):")
print(run("curl -v http://127.0.0.1:10001/"))
