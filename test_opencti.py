"""Test OpenCTI connectivity."""
import requests

TOKEN = "2cd651a3-950e-468a-af71-c4025ab36a2e"
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {TOKEN}",
}
QUERY = '{"query": "{ about { version } }"}'

for url in [
    "http://192.168.3.66:8080",
    "http://127.0.0.1:8888",
    "http://127.0.0.1:8080",
]:
    try:
        r = requests.post(f"{url}/graphql", headers=HEADERS, data=QUERY, timeout=5)
        print(f"{url}: {r.status_code} -> {r.text[:200]}")
    except Exception as e:
        print(f"{url}: {type(e).__name__}: {e}")
