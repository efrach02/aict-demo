import asyncio
from datetime import datetime, timezone
from html import escape
import json
from typing import Any, Dict, List

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse

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
subscribers: List[asyncio.Queue] = []


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
        "method": request.method,
        "path": request.url.path,
        "url": str(request.url),
        "ip": _get_request_ip(request),
        "user_agent": request.headers.get("user-agent"),
        "referer": request.headers.get("referer"),
        "headers": dict(request.headers),
    }


def _build_summary(entry: Dict[str, Any]) -> str:
    if "body" in entry:
        return f"JSON: {json.dumps(entry['body'], ensure_ascii=False)}"
    return f"Query: {json.dumps(entry.get('params', {}), ensure_ascii=False)}"


def _record_entry(entry: Dict[str, Any]) -> None:
    entries.append(entry)
    for queue in list(subscribers):
        try:
            queue.put_nowait(entry)
        except asyncio.QueueFull:
            continue


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
    _record_entry(entry)
    return Response(content=PIXEL, media_type="image/png")


@app.post("/log")
async def log_post(request: Request) -> JSONResponse:
    payload = await request.json()
    entry = _base_entry(request)
    entry["params"] = dict(request.query_params)
    entry["body"] = payload
    _record_entry(entry)
    return JSONResponse({"status": "ok"})


@app.get("/stream")
async def stream_logs(request: Request) -> StreamingResponse:
    async def event_generator() -> Any:
        queue: asyncio.Queue = asyncio.Queue(maxsize=500)
        subscribers.append(queue)
        try:
            yield "retry: 2000\n\n"
            for entry in entries[-100:]:
                payload = json.dumps(entry, ensure_ascii=False, default=str)
                yield f"event: log\ndata: {payload}\n\n"

            while True:
                if await request.is_disconnected():
                    break
                try:
                    entry = await asyncio.wait_for(queue.get(), timeout=15)
                    payload = json.dumps(entry, ensure_ascii=False, default=str)
                    yield f"event: log\ndata: {payload}\n\n"
                except TimeoutError:
                    yield "event: heartbeat\ndata: {}\n\n"
        finally:
            if queue in subscribers:
                subscribers.remove(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )


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


@app.get("/logs", response_class=HTMLResponse)
async def live_dashboard() -> HTMLResponse:
    return HTMLResponse(
        """
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <title>Live Logs</title>
          <style>
            body {
              margin: 0;
              padding: 1rem;
              background: #0d0d0d;
              color: #e6e6e6;
              font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
            }
            h1 {
              margin: 0 0 1rem 0;
              font-size: 1.1rem;
            }
            .toolbar {
              display: flex;
              gap: 0.75rem;
              margin-bottom: 1rem;
            }
            button {
              background: #222;
              color: #eee;
              border: 1px solid #444;
              padding: 0.4rem 0.7rem;
              cursor: pointer;
            }
            #status { color: #8bd5ff; }
            #feed {
              display: grid;
              gap: 0.75rem;
            }
            .card {
              border: 1px solid #333;
              background: #171717;
              padding: 0.75rem;
            }
            .meta {
              color: #bcbcbc;
              margin-bottom: 0.5rem;
            }
            pre {
              margin: 0;
              white-space: pre-wrap;
              word-break: break-word;
            }
          </style>
        </head>
        <body>
          <h1>Live Verbose Request Stream</h1>
          <div class="toolbar">
            <button id="clearBtn">Clear View</button>
            <div id="status">Connecting...</div>
          </div>
          <div id="feed"></div>
          <script>
            const feed = document.getElementById("feed");
            const statusEl = document.getElementById("status");
            const clearBtn = document.getElementById("clearBtn");
            const stream = new EventSource("/stream");

            function addEntry(entry) {
              const card = document.createElement("div");
              card.className = "card";
              const meta = document.createElement("div");
              meta.className = "meta";
              meta.textContent = `${entry.timestamp} | ${entry.method} ${entry.path} | ${entry.ip}`;
              const pre = document.createElement("pre");
              pre.textContent = JSON.stringify(entry, null, 2);
              card.appendChild(meta);
              card.appendChild(pre);
              feed.prepend(card);
            }

            stream.addEventListener("open", () => {
              statusEl.textContent = "Connected";
            });

            stream.addEventListener("error", () => {
              statusEl.textContent = "Disconnected. Retrying...";
            });

            stream.addEventListener("log", (event) => {
              statusEl.textContent = "Connected";
              const data = JSON.parse(event.data);
              addEntry(data);
            });

            clearBtn.addEventListener("click", () => {
              feed.innerHTML = "";
            });
          </script>
        </body>
        </html>
        """
    )


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok"}
