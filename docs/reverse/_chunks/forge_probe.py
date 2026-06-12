"""
纯算法伪造探测 —— 不经浏览器, Python 直接生成 x-statsig-id 打 grok 服务端。

验证目标: 纯算签名能否通过服务端检测。
关键: 用 curl_cffi impersonate Chrome 复刻真实 TLS/HTTP2 指纹绕过 Cloudflare,
      这样失败/成功才真正反映 x-statsig-id 校验, 而非 CF bot 拦截。

分层诊断:
  L0 cookie 有效性 + Cloudflare 是否放行 (TLS 指纹能否过 CF)
  L1 用当前会话真实 Q (HTTP 抓 meta) 对比 session D 的 Q
  L2a 用当前会话真实 Q + 纯算 SALT? -> 无 SALT(需浏览器), 跳过
  L2b 用 session D 自洽 (Q_D, SALT_D) + 纯算新签名 -> GET /rest/* -> 看状态
  L3 对照: 同请求但 *不带* x-statsig-id, 看服务端是否本来就不校验

cookie 通过环境变量 GROK_COOKIE 传入 (形如 "sso=...; sso-rw=..."),不写入任何文件。
代理通过 GROK_PROXY 传入 (默认 http://127.0.0.1:7897)。
"""
from __future__ import annotations

import os
import sys
import time

from curl_cffi import requests as creq

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from x_statsig_id import (  # noqa: E402
    BASE_EPOCH,
    ExtractedFingerprint,
    extract_q_from_html,
    _SELF_TEST_D,
)

BASE = "https://grok.com"
IMPERSONATE = "chrome131"

COOKIE = os.environ.get("GROK_COOKIE", "").strip()
if not COOKIE:
    print("ERROR: 需要环境变量 GROK_COOKIE")
    sys.exit(1)

PROXY = os.environ.get("GROK_PROXY", "http://127.0.0.1:7897").strip()
PROXIES = {"http": PROXY, "https": PROXY} if PROXY else None


def base_headers() -> dict:
    # curl_cffi impersonate 会自动注入与 Chrome 一致的 UA / sec-ch-ua / Accept 等,
    # 这里只补业务必需头, 避免覆盖指纹相关头。
    return {
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Cookie": COOKIE,
        "Referer": BASE + "/",
        "Origin": BASE,
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
    }


def is_cf_challenge(resp) -> bool:
    body_lower = resp.text[:2000].lower()
    return ("just a moment" in body_lower
            or "challenge-platform" in body_lower
            or "cf-mitigated" in {k.lower() for k in resp.headers})


def main() -> None:
    sess = creq.Session(impersonate=IMPERSONATE, proxies=PROXIES, timeout=25)

    # ---- L0: 抓首页, 看 CF 是否放行 ----
    print("=" * 60)
    print(f"[L0] GET / (impersonate={IMPERSONATE}, proxy={PROXY})")
    try:
        r0 = sess.get(BASE + "/", headers=base_headers())
    except Exception as e:
        print(f"  连接异常: {e!r}")
        return
    print(f"  HTTP {r0.status_code}  len={len(r0.text)}")
    print(f"  Cloudflare challenge: {is_cf_challenge(r0)}")
    print(f"  server={r0.headers.get('server')}  cf-ray={r0.headers.get('cf-ray')}")

    # ---- L1: 抓当前会话真实 Q, 对比 session D ----
    cur_q = None
    try:
        cur_q = extract_q_from_html(r0.text)
        print(f"\n[L1] 当前会话 Q (HTTP meta): {len(cur_q)}B, "
              f"pick=Q[5]%4={cur_q[5] % 4}, a=Q[45]%16={cur_q[45] % 16}")
    except Exception as e:
        print(f"\n[L1] 未能从 HTML 抓到 Q: {e!r}")

    q_d = ExtractedFingerprint(_SELF_TEST_D["q_b64"], _SELF_TEST_D["salt"]).Q
    if cur_q:
        print(f"     当前 Q == session D Q ? {cur_q == q_d}")

    # ---- L2b: 纯算伪造签名 -> 打只读端点 ----
    fp_d = ExtractedFingerprint(_SELF_TEST_D["q_b64"], _SELF_TEST_D["salt"])
    method, path = "GET", "/rest/app-chat/conversations"
    ts = time.time()
    tf = int(ts) - BASE_EPOCH
    sig = fp_d.sign(method, path, ts=ts)
    print("\n[L2b] 纯算伪造签名打服务端 (session D 自洽指纹 Q_D+SALT_D)")
    print(f"     {method} {path}?pageSize=1")
    print(f"     tf={tf}  x-statsig-id(len={len(sig)})={sig[:44]}...")

    h = base_headers()
    h["x-statsig-id"] = sig
    try:
        r2 = sess.get(BASE + path + "?pageSize=1", headers=h)
    except Exception as e:
        print(f"     请求异常: {e!r}")
        return
    print(f"     -> HTTP {r2.status_code}  cf={is_cf_challenge(r2)}")
    print(f"     content-type={r2.headers.get('content-type', '')}")
    print(f"     body[:300]={r2.text[:300].replace(chr(10), ' ')}")

    # ---- L3: 对照组 —— 不带 x-statsig-id, 看是否本来就放行 ----
    print("\n[L3] 对照: 同请求但完全不带 x-statsig-id")
    try:
        r3 = sess.get(BASE + path + "?pageSize=1", headers=base_headers())
        print(f"     -> HTTP {r3.status_code}  cf={is_cf_challenge(r3)}  "
              f"body[:120]={r3.text[:120].replace(chr(10), ' ')}")
    except Exception as e:
        print(f"     请求异常: {e!r}")

    # ---- L4: 对照组 —— 带一个明显无效的 x-statsig-id, 看是否被专门拒 ----
    print("\n[L4] 对照: 带垃圾 x-statsig-id (94 个 'A')")
    try:
        hbad = base_headers()
        hbad["x-statsig-id"] = "A" * 94
        r4 = sess.get(BASE + path + "?pageSize=1", headers=hbad)
        print(f"     -> HTTP {r4.status_code}  cf={is_cf_challenge(r4)}  "
              f"body[:120]={r4.text[:120].replace(chr(10), ' ')}")
    except Exception as e:
        print(f"     请求异常: {e!r}")

    # ---- 结论 ----
    print("\n" + "=" * 60)
    if is_cf_challenge(r2):
        print("[结论] 仍卡在 Cloudflare, 未到 statsig 校验层。")
    elif r2.status_code == 200:
        print("[结论] 纯算伪造签名 通过 ✅ (服务端接受了 Python 生成的 x-statsig-id)")
    else:
        print(f"[结论] 过了 CF, 但服务端拒绝 ({r2.status_code})。")
        print("       对比 L3(不带)/L4(垃圾) 的状态码可判断是否 statsig 专项拦截。")


if __name__ == "__main__":
    main()
