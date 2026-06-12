"""
x-statsig-id 服务端校验严格度 —— 对照矩阵实测。

用从真实浏览器抓出的【完整 cookie(已过 CF)】固定住 Cloudflare 变量,
纯 Python(curl_cffi impersonate Chrome)对同一只读端点发多个变体,
唯一变量是 x-statsig-id 头本身, 看服务端放行哪些:

  V0 真实 x0 兜底     —— 浏览器当前就用它过的 200 (baseline)
  V1 纯算伪造真签名   —— session D 的 (Q,SALT), 纯 Python 新 tf+r 生成 94 字符 ← 核心验证
  V2 自构造 x0 兜底   —— official_fallback_value()
  V3 垃圾 94 个 'A'
  V4 完全不带 x-statsig-id

cookie 经环境变量 GROK_COOKIE 传入(不写盘)。
代理经 HTTPS_PROXY / ALL_PROXY 或默认 127.0.0.1:7897。
"""
from __future__ import annotations

import base64
import os
import sys
import time

from curl_cffi import requests as cffi

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from x_statsig_id import (  # noqa: E402
    BASE_EPOCH,
    ExtractedFingerprint,
    official_fallback_value,
    _SELF_TEST_D,
)

BASE = "https://grok.com"
PATH = "/rest/app-chat/conversations"
QS = "?pageSize=1"

COOKIE = os.environ.get("GROK_COOKIE", "").strip()
if not COOKIE:
    print("ERROR: 需要环境变量 GROK_COOKIE (从浏览器抓的完整 cookie)")
    sys.exit(1)

PROXY = (os.environ.get("HTTPS_PROXY") or os.environ.get("ALL_PROXY")
         or "http://127.0.0.1:7897")
PROXIES = {"http": PROXY, "https": PROXY}

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")


def headers(statsig: str | None) -> dict:
    h = {
        "accept": "*/*",
        "accept-language": "zh,en;q=0.9",
        "cookie": COOKIE,
        "referer": BASE + "/",
        "user-agent": UA,
        "sec-ch-ua": '"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "x-xai-request-id": "7b920fa5-63e9-4620-876d-aa776fc3e420",
    }
    if statsig is not None:
        h["x-statsig-id"] = statsig
    return h


def probe(label: str, statsig: str | None) -> None:
    sig_show = (statsig[:46] + "…") if statsig and len(statsig) > 46 else statsig
    try:
        r = cffi.get(BASE + PATH + QS, headers=headers(statsig),
                     proxies=PROXIES, impersonate="chrome", timeout=25)
    except Exception as e:
        print(f"  {label:<22} 请求异常: {e!r}")
        return
    body = r.text[:160].replace("\n", " ")
    cf = "just a moment" in body.lower()
    tag = "CF拦截" if cf else ("✅放行" if r.status_code == 200 else "服务端拒")
    print(f"  {label:<22} HTTP {r.status_code}  [{tag}]")
    print(f"  {'':<22} statsig={sig_show}")
    print(f"  {'':<22} body[:160]={body}")
    print()


def main() -> None:
    print("=" * 64)
    print("x-statsig-id 服务端校验严格度 — 对照矩阵")
    print(f"proxy={PROXY}  path={PATH}{QS}")
    print("=" * 64)

    # V0: 真实 x0 兜底 (浏览器抓到的那条原值, 已过 200)
    real_x0 = base64.b64encode(
        b"x0:TypeError: Cannot read properties of undefined (reading 'childNodes')"
    ).decode()

    # V1: 纯算伪造真签名 (session D 自洽 Q+SALT, 全新 tf + 随机 r)
    fp_d = ExtractedFingerprint(_SELF_TEST_D["q_b64"], _SELF_TEST_D["salt"])
    ts = time.time()
    tf = int(ts) - BASE_EPOCH
    forged = fp_d.sign("GET", PATH, ts=ts)

    print(f"[V1 纯算伪造] tf={tf} len={len(forged)}\n")

    probe("V0 真实x0兜底", real_x0)
    probe("V1 纯算伪造真签名★", forged)
    probe("V2 自构造x0兜底", official_fallback_value())
    probe("V3 垃圾94A", "A" * 94)
    probe("V4 不带statsig", None)

    print("=" * 64)
    print("解读:")
    print("  若 V1==200 -> 纯算伪造真签名【通过】服务端 statsig 校验。")
    print("  若 V0/V2==200 但 V1!=200 -> 服务端对真签名反而更严(或 Q 须绑会话)。")
    print("  若 V3/V4 也 200 -> 该端点根本不校验 statsig(宽松)。")
    print("  若全部 CF拦截 -> cookie 未含有效 CF 通行证, 仍未隔离出 statsig 变量。")


if __name__ == "__main__":
    main()
