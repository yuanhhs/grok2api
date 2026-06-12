"""
两账号轮询对话 —— 探测 grok.com 是否触发风控。

按用户要求:
  - x-statsig-id 字段 用【真实算法】生成 (gen_x_statsig_id, 非 x0 兜底)
  - 其余 (端点/payload/请求头/cookie/代理) 沿用本地脚本方式 (对齐 grok2api build_http_headers)

真实算法需要自洽的 (Q, SALT):
  SALT = z(Q) 是浏览器渲染指纹, 本环境 z() 抛错无法现算。
  这里用上个会话实测自洽的历史对 (Q_B, SALT_B=z(Q_B)), 生成结构合法的 94 字符签名。
  注: 服务端连 x0 垃圾值都接受(200), 故签名是否被严格校验存疑;
      本实验主要测「同一出口IP轮换两账号 + 真签名」的请求模式是否被风控。

安全: 两账号 sso / cf_clearance 经环境变量传入, 文件内不含任何密钥。

用法:
  GROK_SSO_1=... GROK_SSO_2=... GROK_CF=<cf_clearance> [GROK_CFBM=<__cf_bm>] \
  python docs/reverse/gen_chat_poll.py [rounds] [delay_s]
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time
import uuid

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from x_statsig_id import gen_x_statsig_id  # 真实签名算法

# --- 真实算法所需的自洽 (Q, SALT) (历史实测; 非密钥, 与 x_statsig_id.py 自测同源) ---
Q_B64 = "BqebdYTA+MGyWtBIzptoJQ4IpBEJMDRK70enPR38XhQ2eN6iQDAXSnojHG4ccMQp"
SALT  = "obfiowerehiring4b58cf100100"   # = z(Q_B), 与 Q 自洽
Q     = base64.b64decode(Q_B64)

CHAT_URL = "https://grok.com/rest/app-chat/conversations/new"
PATH     = "/rest/app-chat/conversations/new"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

PROXY   = os.environ.get("GROK_PROXY", "http://127.0.0.1:7897")
PROXIES = {"http": PROXY, "https": PROXY}

SSO_1 = os.environ.get("GROK_SSO_1", "").strip()
SSO_2 = os.environ.get("GROK_SSO_2", "").strip()
CF    = os.environ.get("GROK_CF", "").strip()       # cf_clearance (IP+UA 绑定, 可跨账号复用)
CFBM  = os.environ.get("GROK_CFBM", "").strip()     # __cf_bm (可选)


def real_statsig() -> str:
    """真实算法生成 x-statsig-id (ts=now, r=random, 每次不同)."""
    return gen_x_statsig_id("POST", PATH, Q, SALT)


def build_cookie(sso: str) -> str:
    """最小 cookie, 对齐 grok2api build_sso_cookie: 仅 sso/sso-rw/cf_clearance(+__cf_bm)."""
    c = f"sso={sso}; sso-rw={sso}"
    if CF:
        c += f"; cf_clearance={CF}"
    if CFBM:
        c += f"; __cf_bm={CFBM}"
    return c


def build_headers(sso: str) -> dict:
    return {
        "Accept": "*/*",
        "Accept-Encoding": "identity",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Content-Type": "application/json",
        "Origin": "https://grok.com",
        "Priority": "u=1, i",
        "Referer": "https://grok.com/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "User-Agent": UA,
        "x-statsig-id": real_statsig(),              # ← 真实算法
        "x-xai-request-id": str(uuid.uuid4()),
        "sec-ch-ua": '"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "Cookie": build_cookie(sso),
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
        "temporary": True,           # 临时会话, 不落库
        "toolOverrides": {
            "gmailSearch": False, "googleCalendarSearch": False,
            "outlookSearch": False, "outlookCalendarSearch": False,
            "googleDriveSearch": False,
        },
    }


def probe_once(name: str, sso: str, prompt: str) -> dict:
    """发一轮对话, 返回观测结果."""
    headers = build_headers(sso)
    statsig = headers["x-statsig-id"]
    t0 = time.time()
    out = {"acct": name, "status": None, "verdict": "", "detail": "",
           "statsig_len": len(statsig), "latency": 0.0}
    try:
        resp = requests.post(
            CHAT_URL, headers=headers, data=json.dumps(build_payload(prompt)),
            proxies=PROXIES, stream=True, timeout=60,
        )
    except Exception as exc:
        out["verdict"] = "EXC"; out["detail"] = str(exc)[:120]
        out["latency"] = time.time() - t0
        return out

    out["status"] = resp.status_code
    out["latency"] = time.time() - t0

    if resp.status_code != 200:
        body = resp.content.decode("utf-8", "replace")[:200]
        if resp.status_code == 403:
            out["verdict"] = "CF_BLOCK/403"
        elif resp.status_code == 401:
            out["verdict"] = "AUTH/401"
        elif resp.status_code == 429:
            out["verdict"] = "RATE_LIMIT/429"
        else:
            out["verdict"] = f"HTTP_{resp.status_code}"
        cf_mit = resp.headers.get("cf-mitigated") or resp.headers.get("cf-chl-bypass")
        out["detail"] = (f"cf-mitigated={cf_mit} " if cf_mit else "") + body.replace("\n", " ")
        return out

    # 200: 读流, 判断是正常回答 / 还是 in-band 错误(风控)
    got_token = False
    inband_err = ""
    frames = 0
    deadline = time.time() + 12
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
            inband_err = json.dumps(obj["error"], ensure_ascii=False)[:160]
            break
        r = (obj.get("result") or {}).get("response") or {}
        if r.get("token"):
            got_token = True
            break
        if r.get("isSoftStop") or r.get("finalMetadata"):
            break
    try:
        resp.close()
    except Exception:
        pass

    if inband_err:
        out["verdict"] = "INBAND_ERR"; out["detail"] = inband_err
    elif got_token:
        out["verdict"] = "OK"; out["detail"] = f"frames={frames}, 正常返回 token"
    else:
        out["verdict"] = "200_NO_TOKEN"; out["detail"] = f"frames={frames}"
    return out


def main() -> int:
    if not (SSO_1 and SSO_2):
        print("ERROR: 需要 GROK_SSO_1 / GROK_SSO_2", file=sys.stderr)
        return 2
    if not CF:
        print("WARN: 未提供 GROK_CF (cf_clearance), 大概率被 Cloudflare 403", file=sys.stderr)

    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 6
    delay  = float(sys.argv[2]) if len(sys.argv) > 2 else 5.0
    accounts = [("acct1", SSO_1), ("acct2", SSO_2)]
    prompts = [
        "用一句话打个招呼。", "2+2等于几？只回答数字。",
        "说出一种颜色。", "今天心情如何？一句话。",
        "推荐一种水果。", "用一个词形容大海。",
    ]

    print(f"[*] 轮询 {rounds} 轮, 间隔 {delay}s, 两账号交替, modeId=fast")
    print(f"[*] x-statsig-id = 真实算法 (gen_x_statsig_id, Q_B/SALT 自洽对)")
    print(f"[*] cf_clearance = {'有' if CF else '无'}   __cf_bm = {'有' if CFBM else '无'}")
    print("-" * 78)

    results = []
    for i in range(rounds):
        name, sso = accounts[i % 2]
        prompt = prompts[i % len(prompts)]
        r = probe_once(name, sso, prompt)
        results.append(r)
        print(f"[{i+1}/{rounds}] {name}  HTTP={r['status']}  {r['verdict']:14s} "
              f"({r['latency']:.1f}s, sig={r['statsig_len']}b)  {r['detail'][:90]}")
        if r["verdict"] in ("CF_BLOCK/403",) and i == 0:
            print("    !! 首轮即被 Cloudflare 拦截 — cf_clearance 失效或风控; 终止")
            break
        if i < rounds - 1:
            time.sleep(delay)

    print("-" * 78)
    ok      = sum(1 for r in results if r["verdict"] == "OK")
    blocked = sum(1 for r in results if r["verdict"] in ("CF_BLOCK/403", "AUTH/401", "RATE_LIMIT/429", "INBAND_ERR"))
    print(f"[汇总] 共 {len(results)} 次: 正常={ok}  受阻={blocked}")
    by_acct = {}
    for r in results:
        by_acct.setdefault(r["acct"], []).append(r["verdict"])
    for a, vs in by_acct.items():
        print(f"    {a}: {vs}")
    if blocked == 0 and ok > 0:
        print("[结论] 未观察到风控: 两账号轮询均正常返回。")
    elif ok > 0 and blocked > 0:
        print("[结论] 部分受阻 — 见各轮 verdict (可能为限流/风控/凭证问题)。")
    else:
        print("[结论] 全部受阻 — 大概率 cf_clearance 失效或已被风控/挑战。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
