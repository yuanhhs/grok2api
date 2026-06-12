"""
本地复刻 grok2api 的 `grok-imagine-image-lite` 文生图 —— 纯 Python, 不起服务。

依据代码 (app/products/openai/images.py 的 _generate_lite / _stream_lite_generate):
  lite 模型不走 WebSocket, 而是走聊天端点:
    POST https://grok.com/rest/app-chat/conversations/new   (SSE 流)
  payload = build_chat_payload(message="Drawing: "+prompt, mode=FAST,
                               imageGenerationCount=2, enableImageGeneration=True)
  响应里找 result.response.cardAttachment.jsonData.image_chunk:
    progress==100 且未被审查时, 图片 URL = "https://assets.grok.com/" + imageUrl

本地复刻的"所有值":
  - 端点 / payload / 请求头 / modeId="fast"  —— 逐字段对齐上面的代码
  - x-statsig-id          —— 官方前端 z() 抛错时的降级兜底值 (已实测服务端接受)
  - Cookie (sso/cf_clearance/...) —— 从环境变量 GROK_COOKIE 读取 (脚本不含密钥)
  - 代理 127.0.0.1:7897   —— cf_clearance 与该出口 IP + UA 绑定, 必须同源

用法:
  GROK_COOKIE='grok_device_id=...; sso=...; cf_clearance=...; __cf_bm=...' \
  python docs/reverse/gen_image_lite.py "a cute cat"
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time
import uuid

import requests

# --- 固定上游常量 (来自 endpoint_table.py / xai_chat.py) ---
CHAT_URL    = "https://grok.com/rest/app-chat/conversations/new"
ASSETS_BASE = "https://assets.grok.com/"

# 浏览器实测 UA (Chrome 149) —— 必须与获取 cf_clearance 时的 UA 一致
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

# x-statsig-id: 官方前端 z(Q) 抛错时的兜底值, 实测服务端接受 (= official_fallback_value())
X_STATSIG_ID = base64.b64encode(
    b"x0:TypeError: Cannot read properties of undefined (reading 'childNodes')"
).decode()

PROXY   = os.environ.get("GROK_PROXY", "http://127.0.0.1:7897")
PROXIES = {"http": PROXY, "https": PROXY}
COOKIE  = os.environ.get("GROK_COOKIE", "").strip()


def build_payload(prompt: str) -> dict:
    """逐字段对齐 build_chat_payload(message="Drawing: "+prompt, mode=FAST)."""
    return {
        "collectionIds": [],
        "connectors": [],
        "deviceEnvInfo": {
            "darkModeEnabled": False, "devicePixelRatio": 2,
            "screenHeight": 1329, "screenWidth": 2056,
            "viewportHeight": 1083, "viewportWidth": 2056,
        },
        "disableMemory": True,
        "disableSearch": False,
        "disableSelfHarmShortCircuit": False,
        "disableTextFollowUps": False,
        "enableImageGeneration": True,
        "enableImageStreaming": True,
        "enableSideBySide": True,
        "fileAttachments": [],
        "forceConcise": False,
        "forceSideBySide": False,
        "imageAttachments": [],
        "imageGenerationCount": 2,
        "isAsyncChat": False,
        "message": f"Drawing: {prompt}",
        "modeId": "fast",
        "responseMetadata": {},
        "returnImageBytes": False,
        "returnRawGrokInXaiRequest": False,
        "searchAllConnectors": False,
        "sendFinalMetadata": True,
        "temporary": True,
        "toolOverrides": {
            "gmailSearch": False, "googleCalendarSearch": False,
            "outlookSearch": False, "outlookCalendarSearch": False,
            "googleDriveSearch": False,
        },
    }


def build_headers() -> dict:
    """逐字段对齐 build_http_headers() + 浏览器实测 client-hints."""
    return {
        "Accept": "*/*",
        "Accept-Encoding": "identity",          # 关闭压缩, 便于流式逐行解析
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Content-Type": "application/json",
        "Origin": "https://grok.com",
        "Priority": "u=1, i",
        "Referer": "https://grok.com/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "User-Agent": UA,
        "x-statsig-id": X_STATSIG_ID,
        "x-xai-request-id": str(uuid.uuid4()),
        "sec-ch-ua": '"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "Cookie": COOKIE,
    }


def _iter_sse(resp) -> "list[dict]":
    """逐行解析 SSE (classify_line 逻辑), yield 每个 JSON 帧."""
    for raw in resp.iter_lines(decode_unicode=True):
        if not raw:
            continue
        s = raw.strip()
        if s.startswith("data:"):
            s = s[5:].strip()
        if s == "[DONE]":
            return
        if not s.startswith("{"):
            continue
        try:
            yield json.loads(s)
        except Exception:
            continue


def main() -> int:
    if not COOKIE:
        print("ERROR: 需要设置环境变量 GROK_COOKIE", file=sys.stderr)
        return 2

    prompt = sys.argv[1] if len(sys.argv) > 1 else (
        "A serene Japanese garden with a red maple tree, a koi pond and a stone "
        "lantern, soft warm sunlight, highly detailed, photorealistic"
    )
    print(f"[*] model   = grok-imagine-image-lite (modeId=fast)")
    print(f"[*] prompt  = {prompt}")
    print(f"[*] proxy   = {PROXY}")
    print(f"[*] statsig = {X_STATSIG_ID[:24]}... (x0 兜底)")

    headers = build_headers()
    payload = build_payload(prompt)

    t0 = time.time()
    resp = requests.post(
        CHAT_URL, headers=headers, data=json.dumps(payload),
        proxies=PROXIES, stream=True, timeout=120,
    )
    print(f"[*] POST {CHAT_URL} -> {resp.status_code}  ({time.time()-t0:.1f}s)")
    if resp.status_code != 200:
        body = resp.content.decode("utf-8", "replace")[:600]
        print("[!] 上游非 200, body 前 600 字:")
        print(body)
        return 1

    image_urls: list[str] = []
    last_prog: dict[str, int] = {}
    frame_count = 0
    for obj in _iter_sse(resp):
        frame_count += 1
        r = (obj.get("result") or {}).get("response") or {}
        card = r.get("cardAttachment")
        if not card:
            continue
        try:
            jd = json.loads(card["jsonData"])
        except Exception:
            continue
        chunk = jd.get("image_chunk")
        if not chunk:
            continue
        uid  = str(chunk.get("imageUuid", ""))[:8]
        prog = chunk.get("progress")
        if isinstance(prog, (int, float)) and last_prog.get(uid) != int(prog):
            last_prog[uid] = int(prog)
            print(f"    image {uid}  progress={int(prog)}%")
        if chunk.get("progress") == 100 and not chunk.get("moderated") and chunk.get("imageUrl"):
            url = ASSETS_BASE + chunk["imageUrl"]
            if url not in image_urls:
                image_urls.append(url)

    print(f"[*] SSE 帧数={frame_count}, 完成图片数={len(image_urls)}")
    if not image_urls:
        print("[!] 未解析到图片 URL")
        return 1

    out_dir = os.path.dirname(os.path.abspath(__file__))
    saved = []
    for i, url in enumerate(image_urls):
        print(f"[*] 下载图片 {i}: {url}")
        ir = requests.get(
            url,
            headers={"User-Agent": UA, "Cookie": COOKIE,
                     "Accept": "image/avif,image/webp,image/*,*/*;q=0.8",
                     "Referer": "https://grok.com/"},
            proxies=PROXIES, timeout=60,
        )
        if ir.status_code != 200 or not ir.content:
            print(f"    下载失败 status={ir.status_code} len={len(ir.content)}")
            continue
        ext = "jpg"
        ct = ir.headers.get("content-type", "")
        if "png" in ct: ext = "png"
        elif "webp" in ct: ext = "webp"
        path = os.path.join(out_dir, f"imagine_lite_{i}.{ext}")
        with open(path, "wb") as f:
            f.write(ir.content)
        saved.append(path)
        print(f"    已保存 {path}  ({len(ir.content)} bytes, {ct})")

    print(f"[OK] 生成 {len(saved)} 张图片: {saved}")
    return 0 if saved else 1


if __name__ == "__main__":
    raise SystemExit(main())
