# Run this script with mitmproxy:
# mitmdump --quiet --listen-port=8081 -s try_http3_proxy.py

from minimal_http3_client import get
from mitmproxy import http
import asyncio


HTTP3_TIMEOUT = 2


async def response(flow):
    if flow.request.method == "GET":
        try:
            data, headers = await asyncio.wait_for(get(flow.request.url, debug=True), HTTP3_TIMEOUT)

            fix_headers = headers
            fix_headers["HTTP3"] = "Loaded-over-HTTP3"
            status_code = 200
            if ':status' in fix_headers:
                status_code = int(fix_headers[':status'].replace(":", ""))
            fix_headers.pop(':status')

            flow.response = http.Response.make(
                status_code,
                bytes(data),
                fix_headers,
            )

            print(f"[SUCCESS] {flow.request.method} {flow.request.url} via HTTP3")

        except Exception as e:
            # flow.response.text = str(e)
            pass
