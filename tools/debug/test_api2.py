import urllib.request
import json

def test():
    url = "http://127.0.0.1:8000/api/attack-chain/pivoting"
    data = json.dumps({
        "start_container_id": "a9b3036eacf0",
        "target_container_id": "d1fccfe8935e"
    }).encode('utf-8')
    req = urllib.request.Request(url, headers={'Content-Type': 'application/json'}, data=data)
    try:
        response = urllib.request.urlopen(req)
        print("Success:", response.read().decode())
    except urllib.error.HTTPError as e:
        print("HTTP Error:", e.code)
        print(e.read().decode())
    except Exception as e:
        print("Other Error:", str(e))

if __name__ == "__main__":
    test()
