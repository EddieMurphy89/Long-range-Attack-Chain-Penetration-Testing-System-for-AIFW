import urllib.request
import urllib.error
import sys

def test_request():
    url = "http://localhost:10004/?id=1'+OR+'1'='1"
    print(f"Testing URL: {url}")
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 SQLMap'})
    try:
        response = urllib.request.urlopen(req, timeout=5)
        print("Status:", response.status)
        print("Headers:", response.getheaders())
        print("Data:", response.read().decode('utf-8')[:200])
    except urllib.error.HTTPError as e:
        print("HTTP Error:", e.code)
        print("Headers:", e.headers.items())
        try:
            print("Error Data:", e.read().decode('utf-8')[:200])
        except:
            pass
    except Exception as e:
        print("Exception:", str(e))

if __name__ == "__main__":
    test_request()
