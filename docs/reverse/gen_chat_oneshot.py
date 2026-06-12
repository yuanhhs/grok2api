"""
单发验证 —— 用【最新真实算法】生成 x-statsig-id, 发一条聊天看能否成功。

实验设计 (单变量对照):
  完全复刻浏览器当前「能用」的那条请求 (同 cookie / 同 UA / 同 client-hints),
  唯一改动 = x-statsig-id 用真实算法 gen_x_statsig_id 现算的 94 字符签名
  (而非官方前端当前发的 x0 兜底值)。
  → 若返回 200 且正常出 token, 说明最新真实算法的签名被服务端接受、调用成功。

真实算法所需自洽 (Q, SALT):
  SALT = z(Q) 是浏览器渲染指纹, 本环境 z() 抛错无法现算;
  用历史实测自洽对 (Q_B, SALT_B=z(Q_B)) —— 结构合法、时间戳取当前、随机头每次不同。

安全: cookie (含 sso/cf_clearance) 仅经环境变量 GROK_COOKIE 传入, 文件内无任何密钥。

用法:
  GROK_COOKIE='grok_device_id=...; sso=...; cf_clearance=...; __cf_bm=...; x-challenge=...; x-signature=...' \
  python docs/reverse/gen_chat_oneshot.py ["你的问题"]
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time
import uuid

import requests

# Windows 控制台默认 GBK, 强制 UTF-8 避免打印中文/emoji 崩溃
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from x_statsig_id import gen_x_statsig_id  # 最新真实算法

# --- 真实算法自洽 (Q, SALT) (历史实测; 非密钥, 与 x_statsig_id.py 自测同源) ---
Q_B64 = "BqebdYTA+MGyWtBIzptoJQ4IpBEJMDRK70enPR38XhQ2eN6iQDAXSnojHG4ccMQp"
SALT  = "obfiowerehiring4b58cf100100"
Q     = base64.b64decode(Q_B64)

CHAT_URL = "https://grok.com/rest/app-chat/conversations/new"
PATH     = "/rest/app-chat/conversations/new"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

PROXY   = os.environ.get("GROK_PROXY", "http://127.0.0.1:7897")
PROXIES = {"http": PROXY, "https": PROXY}
COOKIE  = os.environ.get("GROK_COOKIE", "").strip()


def build_headers(statsig: str) -> dict:
    """复刻浏览器真实请求头, 仅 x-statsig-id 用真实算法值。"""
    return {
        "Accept": "*/*",
        "Accept-Encoding": "identity",          # 关压缩, 便于逐行解析 SSE
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Content-Type": "application/json",
        "Origin": "https://grok.com",
        "Priority": "u=1, i",
        "Referer": "https://grok.com/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "User-Agent": UA,
        "x-statsig-id": statsig,                 # ← 最新真实算法
        "x-xai-request-id": str(uuid.uuid4()),
        "sec-ch-ua": '"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "Cookie": COOKIE,
    }


def build_payload(prompt: str) -> dict:
    return {
        "collectionIds": [], "connectors": [],
        "deviceEnvInfo": {
            "darkModeEnabled": False, "devicePixelRatio": 2,
            "screenHeight": 1329, "screenWidth": 2056,
            "viewportHeight": 1083, "viewportWidth": 2056,
        },
        "disableMemory": True, "disableSearch": False,
        "disableSelfHarmShortCircuit": False, "disableTextFollowUps": False,
        "enableImageGeneration": False, "enableImageStreaming": False,
        "enableSideBySide": False,
        "fileAttachments": [], "forceConcise": False, "forceSideBySide": False,
        "imageAttachments": [], "imageGenerationCount": 0,
        "isAsyncChat": False,
        "message": prompt,
        "modeId": "fast",
        "responseMetadata": {},
        "returnImageBytes": False, "returnRawGrokInXaiRequest": False,
        "searchAllConnectors": False, "sendFinalMetadata": True,
        "temporary": True,
        "toolOverrides": {
            "gmailSearch": False, "googleCalendarSearch": False,
            "outlookSearch": False, "outlookCalendarSearch": False,
            "googleDriveSearch": False,
        },
    }


def main() -> int:
    if not COOKIE:
        print("ERROR: 需要设置环境变量 GROK_COOKIE", file=sys.stderr)
        return 2

    prompt = sys.argv[1] if len(sys.argv) > 1 else "用一句话介绍你自己。"

    statsig = gen_x_statsig_id("POST", PATH, Q, SALT)   # 现算: ts=now, r=random
    print(f"[*] x-statsig-id (真实算法, {len(statsig)} 字符): {statsig[:40]}...")
    print(f"[*] prompt = {prompt}")
    print(f"[*] proxy  = {PROXY}")
    print(f"[*] cookie 字段: " + ", ".join(
        c.split('=')[0].strip() for c in COOKIE.split(';') if c.strip()))
    print("-" * 70)

    headers = build_headers(statsig)
    t0 = time.time()
    try:
        resp = requests.post(
            CHAT_URL, headers=headers, data=json.dumps(build_payload(prompt)),
            proxies=PROXIES, stream=True, timeout=60,
        )
    except Exception as exc:
        print(f"[EXC] 请求异常: {exc}")
        return 1

    dt = time.time() - t0
    print(f"[*] HTTP {resp.status_code}  ({dt:.1f}s)")
    cf_mit = resp.headers.get("cf-mitigated")
    if cf_mit:
        print(f"[*] cf-mitigated: {cf_mit}")
    print(f"[*] cf-ray: {resp.headers.get('cf-ray', '-')}  server: {resp.headers.get('server','-')}")

    if resp.status_code != 200:
        body = resp.content.decode("utf-8", "replace")[:500]
        print(f"[!] 非 200, body 前 500 字:\n{body}")
        verdict = {403: "被拦截(CF/风控)", 401: "未授权(sso?)", 429: "限流"}.get(
            resp.status_code, f"HTTP_{resp.status_code}")
        print(f"\n[结论] 调用失败 — {verdict}")
        return 1

    # 200: 读流, 拼出回答, 判断是否真正成功
    answer = []
    inband_err = ""
    frames = 0
    deadline = time.time() + 30
    for raw in resp.iter_lines(decode_unicode=True):
        if time.time() > deadline:
            break
        if not raw:
            continue
        s = raw.strip()
        if s.startswith("data:"):
            s = s[5:].strip()
        if s == "[DONE]" or not s.startswith("{"):
            continue
        try:
            obj = json.loads(s)
        except Exception:
            continue
        frames += 1
        if isinstance(obj.get("error"), dict):
            inband_err = json.dumps(obj["error"], ensure_ascii=False)[:300]
            break
        r = (obj.get("result") or {}).get("response") or {}
        tok = r.get("token")
        if tok:
            answer.append(tok)
        if r.get("isSoftStop") or r.get("finalMetadata"):
            break
    try:
        resp.close()
    except Exception:
        pass

    print(f"[*] SSE 帧数={frames}")
    if inband_err:
        print(f"[!] 流内错误: {inband_err}")
        print(f"\n[结论] HTTP 200 但流内报错 — 可能被软风控")
        return 1
    if answer:
        text = "".join(answer)
        print(f"[*] 模型回答: {text[:200]}")
        print(f"\n[结论] ✅ 调用成功 — 最新真实算法 x-statsig-id 被接受, 正常出 token ({len(text)} 字)")
        return 0
    print(f"\n[结论] HTTP 200 但未取到 token (帧数={frames}) — 需查看原始流")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
