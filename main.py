from datetime import datetime, timezone
from html import escape
import json
from typing import Any, Dict, List

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response

app = FastAPI(title="Webhook Receiver & Request Inspector")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PIXEL = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
    b"\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    b"\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01"
    b"\r\n\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)

entries: List[Dict[str, Any]] = []


def _get_request_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _base_entry(request: Request) -> Dict[str, Any]:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip": _get_request_ip(request),
        "user_agent": request.headers.get("user-agent"),
        "referer": request.headers.get("referer"),
    }


def _build_summary(entry: Dict[str, Any]) -> str:
    if "body" in entry:
        return f"JSON: {json.dumps(entry['body'], ensure_ascii=False)}"
    return f"Query: {json.dumps(entry.get('params', {}), ensure_ascii=False)}"


@app.get("/", response_class=HTMLResponse)
async def landing_page() -> HTMLResponse:
    return HTMLResponse(
        """
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <title>Hello</title>
          <style>
            body {
              margin: 0;
              min-height: 100vh;
              display: grid;
              place-items: center;
              background: #111;
              color: #eee;
              font-family: Arial, sans-serif;
            }
            h1 { font-size: 2rem; }
          </style>
        </head>
        <body>
          <h1>Hello World</h1>
        </body>
        </html>
        """
    )


@app.get("/log")
async def log_get(request: Request) -> Response:
    params = dict(request.query_params)
    entry = _base_entry(request)
    entry["params"] = params
    entries.append(entry)
    return Response(content=PIXEL, media_type="image/png")


@app.post("/log")
async def log_post(request: Request) -> JSONResponse:
    payload = await request.json()
    entry = _base_entry(request)
    entry["params"] = dict(request.query_params)
    entry["body"] = payload
    entries.append(entry)
    return JSONResponse({"status": "ok"})


@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard() -> HTMLResponse:
    rows = []
    for entry in reversed(entries):
        raw_json = json.dumps(entry, ensure_ascii=False, indent=2, default=str)
        rows.append(
            f"""
            <tr>
                <td>{escape(str(entry.get('timestamp', '')))}</td>
                <td>{escape(str(entry.get('ip', '')))}</td>
                <td><pre>{escape(_build_summary(entry))}</pre></td>
                <td><pre>{escape(str(entry.get('user_agent', '')))}</pre></td>
                <td><pre>{escape(str(entry.get('referer', '')))}</pre></td>
                <td><pre>{escape(raw_json)}</pre></td>
            </tr>
            """
        )

    html = f"""
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8" />
      <meta http-equiv="refresh" content="5" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>Request Inspector</title>
      <style>
        body {{
          margin: 0;
          padding: 1rem;
          background: #111;
          color: #eee;
          font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
        }}
        h1 {{
          margin: 0 0 1rem 0;
          font-size: 1.1rem;
        }}
        table {{
          width: 100%;
          border-collapse: collapse;
          table-layout: fixed;
          font-size: 0.85rem;
        }}
        th, td {{
          border: 1px solid #333;
          padding: 0.5rem;
          vertical-align: top;
          word-wrap: break-word;
        }}
        th {{
          background: #1c1c1c;
          position: sticky;
          top: 0;
          z-index: 1;
        }}
        tr:nth-child(even) {{
          background: #161616;
        }}
        pre {{
          margin: 0;
          white-space: pre-wrap;
          word-break: break-word;
        }}
      </style>
    </head>
    <body>
      <h1>Webhook Receiver & Request Inspector ({len(entries)} total)</h1>
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>IP</th>
            <th>Params/Body summary</th>
            <th>User-Agent</th>
            <th>Referer</th>
            <th>Raw Data (JSON)</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rows)}
        </tbody>
      </table>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok"}
