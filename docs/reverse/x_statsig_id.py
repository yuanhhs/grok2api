"""
grok.com `x-statsig-id` 请求头签名算法 —— 还原实现（参考 / 验证用）。

配套分析文档: docs/reverse/x-statsig-id-逆向分析.md

状态:
  - 核心签名算法 : 已 100% 还原并端到端验证 (Python 逐字符复刻浏览器真实 header)
                    三组独立会话各自验证: 会话 B (1 样本) + 会话 C (8/8, 见 _SELF_TEST_C)
                    + 会话 D (当前 build 真签名正常工作, 与网络层真值闭合, 见 _SELF_TEST_D)
  - Q (48B 设备指纹): 来源 = SSR <meta name="grok-site―verification"> 的 content(base64)
  - SALT = f(Q)   : 已揭示 = "obfiowerehiring" + z(Q); z(Q) 是浏览器 CSS/Web-Animations
                    渲染指纹。**拼装层已破解** (见 salt_assembly.py): 最唬人的那串
                    "…28f5c28f6…" 其实是 JS Number.toString(16) 浮点输出, 已逐字符复刻。
                    z(Q) 五步里唯一非纯算输入是 m 矩阵 (运行时 React 挂载的 SVG <path d>,
                    build 常量但不在 SSR HTML / chunk), color 取 m 固定行、transform 是
                    Q→C→旋转角。纯算并非"不可能", 只是 m 须每 build 提取一次, 不划算。
                    z(Q) 字节索引随 grok 发版漂移 (旧 Q[22/14/36/33] vs 新 Q[45/9/36/30]+Q[5]%4)。
  - 生产落地    : 用提取式 ExtractedFingerprint —— 每会话浏览器 hook 一次 digest 读 SALT,
                    之后纯 Python 高频签名。天然抗 build 变化 (读的是当前代码实算的 SALT)。
                    会话 D 即用此法在当前 build 实测跑通 (hook 主世界 digest 读 SALT)。

运行时关键发现 (2026-06-11, Chrome 149 + CDP + 代理 + grok 新构建 sentry-release 4dc4856…):
  - grok.com 官方前端的 z(Q) 在本环境抛 `TypeError: Cannot read properties of
    undefined (reading 'childNodes')`, fetch 中间件 catch 后**自身发送降级兜底值**
    btoa("x0:"+err); 服务端对 /rest/modes、/rest/app-chat/conversations、
    /rest/workspaces 等端点**照常返回 200**。
  - => x-statsig-id 现阶段更像「尽力而为的遥测」, 真正反爬闸口是 cf_clearance /
    x-challenge / x-signature / sso。该 x0 兜底值可直接复用 (见 official_fallback_value)。
  - grok2api 现有 _statsig_id() 用前缀 "e:"(错误体相同), 与官方观测前缀 "x0:" 不符。

算法概览:
    timeFactor = floor(now/1000) - 1682924400          # 基准 2023-05-01T07:00:00Z
    message    = "{METHOD}!{pathname}!{timeFactor}" + SALT
    digest     = SHA-256(message)                       # 纯 SHA-256, 非 HMAC
    r          = floor(random()*256)                    # 每次调用随机 1 字节
    payload(70B) = [r] + Q(48) + uint32LE(timeFactor)(4) + digest[:16](16) + [3]
    out[i]     = payload[i] ^ r   (i>=1),  out[0] = r   # 随机头异或掩码
    x-statsig-id = base64(out).rstrip("=")
"""
from __future__ import annotations

import base64
import hashlib
import random
import re
import struct
import time

# --- 常量 (实测确认) ---
BASE_EPOCH = 1682924400          # 2023-05-01T07:00:00.000Z, 秒
SALT_PREFIX = "obfiowerehiring"  # 字面常量 ("obf io we're hiring" 招聘彩蛋)
TAIL_L = 3                       # 输出 payload 尾字节常量
# meta name 中间是 U+2015 (―) 全角横线, 不是普通 '-' (刻意防搜索/选择器)
META_NAME = "grok-site―verification"

# meta 标签提取 Q: 兼容 name/content 任意先后顺序
_META_RE_NC = re.compile(
    r'<meta[^>]*name=["\']grok-site―verification["\'][^>]*content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_META_RE_CN = re.compile(
    r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']grok-site―verification["\']',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Q (48 字节设备指纹) —— 来自服务端 SSR 下发的 meta 标签
# ---------------------------------------------------------------------------
def extract_q_from_html(html: str) -> bytes:
    """从 grok.com 首页 HTML 解析 48 字节设备指纹 Q。"""
    m = _META_RE_NC.search(html) or _META_RE_CN.search(html)
    if not m:
        raise ValueError("未找到 grok-site―verification meta 标签")
    q = base64.b64decode(m.group(1))
    if len(q) != 48:
        raise ValueError(f"Q 长度应为 48, 实际 {len(q)}")
    return q


def fetch_q(base_url: str = "https://grok.com/", proxies=None, timeout: int = 15) -> bytes:
    """HTTP GET 首页并提取 Q (需要 requests)。每次 GET 返回的 Q 不同。"""
    import requests  # 延迟导入, 仅在需要联网抓取时依赖

    resp = requests.get(
        base_url,
        timeout=timeout,
        proxies=proxies,
        headers={
            "accept": "text/html",
            "user-agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
            ),
        },
    )
    resp.raise_for_status()
    return extract_q_from_html(resp.text)


# ---------------------------------------------------------------------------
# SALT = SALT_PREFIX + z(Q)
#
# z(Q) 经动态调试完全揭示 = **浏览器 CSS / Web-Animations 渲染指纹**:
#   1. m = h(".r-7ya3u", Q): 从页面 CSS 提取 16x11 颜色矩阵 (CSS 指纹)
#   2. a = Q[22] % 16;  C = (Q[14]%16 + Q[36]%16) - Q[33]%16  (-> animation.currentTime)
#   3. el = document.createElement(<tag>); document.body.append(el)
#   4. el.animate(<由 m[a] 派生的 keyframes>);  animation.currentTime = g(C)
#   5. cs = getComputedStyle(el); 读 cs.color 与 cs.transform
#   6. z(Q) = 提取 (cs.color + cs.transform) 中所有数字, 各自 ->hex 后拼接
#
# **字节依赖 (静态解混淆确认, 2026-06-11)**: z(Q) 只读 Q 的 4 个字节, 各自先 %16:
#   选颜色组 a + 合成动画时刻 C。=> a 取 16 种, C 取 <=46 种 -> (a,C) <=736 ->
#   理论上全部可能 SALT 可枚举 (档次 B 查找表)。颜色矩阵是 build-time CSS 常量, 与 Q 无关。
#
# ⚠️ 但活体断点复测 (2026-06-11) 否决了档次 B —— 它"按 build 版本绑定":
#   ① 依赖的 4 个字节索引随 grok 发版漂移 (结构不变, 具体索引每次变):
#        旧 build (0u3n0ftyjlugz.js): a=Q[22]%16,  C=(Q[14]+Q[36]-Q[33])%16
#        新 build (0vu5gegy_t7j9.js): a=Q[45]%16,  C=(Q[9] +Q[36]-Q[30])%16  (另含 Q[5]%4 选矩阵)
#   ② color 与 transform 都是 Web-Animations 在 currentTime 的"活体插值":
#        断点暂停时 JS 冻结/动画时钟停摆 -> 只能拿起始帧 (实测枚举 736 项 distinct 仅 16、
#        transform 全平凡、color 也错); 必须在未暂停的页面里调 z 才正确。
#   => grok 每发版: 4 字节索引漂移 + 颜色矩阵变 -> 整张表作废, 需重新逆向 chunk + 重新活体标定。
#      与"纯 Python 永不用浏览器"初衷相悖。**生产用档次 A (每会话 hook digest 读 SALT),
#      天然抗 build 变化 —— 它读当前代码实际算出的值, 不关心字节索引怎么漂。**
#
# 实例 1 (会话 B, Q[22]=52 -> a=4, 平凡 transform):
#   m[4][:3] = [75, 88, 207]        -> color "rgb(75, 88, 207)"   -> "4b58cf"
#   transform = matrix(1,0,0,1,0,0) -> 数字 1,0,0,1,0,0            -> "100100"
#   => z(Q) = "4b58cf100100",  SALT = "obfiowerehiring4b58cf100100"  (12 hex)
#
# 实例 2 (会话 C, 2026-06-11 实测, 非平凡 transform 含 rotate/矩阵插值):
#   Q = "+zl265ilrGs7+pUQRq6/28qhPaRSaf+UOGQUPUHsWFyghBg7B91O70t4iK9eEIg+"
#   => z(Q) = "2246bf10028f5c28f5c28f60028f5c28f5c28f6100"  (42 hex, 更长)
#      SALT = "obfiowerehiring2246bf10028f5c28f5c28f60028f5c28f5c28f6100"
#   该会话 8 个端点的真签名已用此 (Q,SALT) Python 逐字符复刻 (见 _SELF_TEST_C)。
#
# 已证实 z(Q) 对固定 Q 确定 (det=true, 跨会话/时间复现; tf 推进期间 SALT 恒定)。
#
# ⚠️ 纯 Python 复刻障碍: color/transform 是元素在 animation.currentTime 时刻的
#    **插值结果**, 由 Chromium Web-Animations 引擎计算 (会话 A 出现浮点尾数
#    999...a 即中间插值)。纯算需复刻: (a) 从 CSS 提取 m; (b) keyframes 构造;
#    (c) 插值数学; (d) getComputedStyle 的 color/transform 序列化与浮点。
#    工程量大且有跨引擎精度风险 -> 生产建议用"提取式"(浏览器/CDP 计算 SALT)。
# ---------------------------------------------------------------------------
def compute_salt(Q: bytes) -> str:
    """
    纯算法复刻 SALT —— 见上方说明。

    因 z(Q) 依赖浏览器渲染引擎 (Web Animations + getComputedStyle), 暂不实现。
    生产环境请使用 ExtractedFingerprint (提取式)。
    """
    raise NotImplementedError(
        "SALT = SALT_PREFIX + z(Q); z(Q) 为浏览器 CSS/Web-Animations 渲染指纹, "
        "纯 Python 复刻需复刻 Chromium 动画插值。请使用 ExtractedFingerprint (提取式)。"
    )


# ---------------------------------------------------------------------------
# 降级兜底值 (x0:) —— 运行时实测, 服务端接受
# ---------------------------------------------------------------------------
# fetch 中间件 ss 的 catch 分支: x-statsig-id = btoa("x0:" + String(error))。
# 当签名函数 z(Q) 抛异常时, 官方前端就发送这个值。
# 2026-06-11 实测 (Chrome 149 + CDP + 代理 + grok 新构建 sentry-release 4dc4856…):
#   z(Q) 的 DOM 指纹读取抛 TypeError ...childNodes, grok.com 官方前端自身即发送
#   下面这个 base64, 服务端对 /rest/modes、/rest/app-chat/conversations、
#   /rest/workspaces 等端点均返回 200。
# => 该值是官方客户端的*失败*路径(非正常 94 字符真签名), 但经验上服务端接受;
#    真正反爬闸口是 cf_clearance / x-challenge / x-signature / sso。
OFFICIAL_X0_FALLBACK_ERR = (
    "x0:TypeError: Cannot read properties of undefined (reading 'childNodes')"
)


def official_fallback_value() -> str:
    """
    返回 grok.com 官方前端在「z(Q) 抛异常」时实际发送的 x-statsig-id (base64)。

    用途: 逐字节复刻官方客户端的*失败*路径值, 经验上服务端接受 (见上方实测)。
    注意 grok2api 现有 headers._statsig_id() 默认值用前缀 "e:"(错误体相同),
    与官方观测前缀 "x0:" 不一致; 若要伪装成官方失败值, 直接用本函数返回。

    注: catch 分支用裸 btoa (不去 '='); 此处错误体字节数恰为 3 的倍数, 无填充。
    """
    return base64.b64encode(OFFICIAL_X0_FALLBACK_ERR.encode()).decode()


class ExtractedFingerprint:
    """
    提取式签名: 保存从真实浏览器一次性提取的会话指纹 (Q, 完整 SALT),
    之后用纯 Python (SHA-256 + 异或) 为该会话任意 method/path 高频签名。

    获取 (Q, SALT) 的方式 (任选):
      - CDP / Playwright 打开 grok.com:
          Q    = atob(<meta name="grok-site―verification">.content)
          SALT = 从 hook 到的 crypto.subtle.digest 输入解析
                 (输入格式 "{METHOD}!{path}!{tf}{SALT}", 去掉前面三段即 SALT)
      - 或: 抓一条真实请求的 x-statsig-id, 配合已知 Q 反推 (见文档 §2.2)。

    前端在单个页面文档生命周期内对所有 API 请求复用同一 (Q, SALT),
    故提取一次即可签名该会话的任意请求, 直到指纹轮换。
    """

    def __init__(self, q_b64: str, salt: str):
        self.Q = base64.b64decode(q_b64)
        if len(self.Q) != 48:
            raise ValueError("Q 必须为 48 字节")
        if not salt.startswith(SALT_PREFIX):
            # 容错: 允许只传 z(Q) 后缀
            salt = SALT_PREFIX + salt
        self.salt = salt

    def sign(self, method: str, pathname: str, ts: float | None = None,
             r: int | None = None) -> str:
        return gen_x_statsig_id(method, pathname, self.Q, self.salt, ts=ts, r=r)


# ---------------------------------------------------------------------------
# 核心: 生成 x-statsig-id (已验证)
# ---------------------------------------------------------------------------
def gen_x_statsig_id(
    method: str,
    pathname: str,
    Q: bytes,
    salt: str,
    ts: float | None = None,
    r: int | None = None,
) -> str:
    """
    生成 x-statsig-id。

    method   : HTTP 方法 (内部转大写)
    pathname : URL 路径 (去 query)
    Q        : 48 字节设备指纹 (extract_q_from_html / fetch_q)
    salt     : compute_salt(Q) 的结果
    ts       : Unix 秒级时间戳 (默认当前时间)
    r        : 随机头字节 0-255 (默认随机; 指定后可复现)

    给定相同 ts/r, 输出与浏览器逐字符一致。
    """
    if len(Q) != 48:
        raise ValueError("Q 必须为 48 字节")
    tf = int(ts if ts is not None else time.time()) - BASE_EPOCH
    msg = f"{method.upper()}!{pathname}!{tf}{salt}".encode()
    digest = hashlib.sha256(msg).digest()  # 32B
    if r is None:
        r = random.randrange(256)
    payload = bytes([r]) + Q + struct.pack("<I", tf) + digest[:16] + bytes([TAIL_L])
    out = bytes([payload[0]] + [b ^ r for b in payload[1:]])
    return base64.b64encode(out).decode().rstrip("=")


# ---------------------------------------------------------------------------
# 自测: 用已知真实样本验证核心算法 (会话 B)
# ---------------------------------------------------------------------------
_SELF_TEST = {
    "q_b64": "BqebdYTA+MGyWtBIzptoJQ4IpBEJMDRK70enPR38XhQ2eN6iQDAXSnojHG4ccMQp",
    "salt": "obfiowerehiring4b58cf100100",
    "method": "GET",
    "pathname": "/rest/app-chat/conversations",
    "tf": 98185915,
    "r": 27,
    "expected": (
        "Gx28gG6f2+PaqUHLU9WAcz4VE78KEisvUfRcvCYG50UPL"
        "WPFuVsrDFFhOAd1B2vfMqApwR5Ow4vsMgP5Hdo011QuVOHqGA"
    ),
}


# 会话 C (2026-06-11 实测, 你过 CF 后 z(Q) 正常工作的真实浏览器环境):
#   - Q 全新, SALT 含非平凡 transform (42 hex, 比会话 B 长得多)
#   - 同一会话连续抓 8 个端点的真签名, Python 用此 (Q, SALT) 逐字符 EXACT 复刻 8/8
#   - 提取手法: hook crypto.subtle.digest 读明文输入 "{M}!{path}!{tf}{SALT}"
#   - 印证: 跨多端点/多随机头 r/多时间戳, 算法稳定; SALT 在 tf 推进期间恒定 (只依赖 Q)
_SELF_TEST_C = {
    "q_b64": "+zl265ilrGs7+pUQRq6/28qhPaRSaf+UOGQUPUHsWFyghBg7B91O70t4iK9eEIg+",
    "salt": "obfiowerehiring2246bf10028f5c28f5c28f60028f5c28f5c28f6100",
    # (method, pathname, tf, r, expected) —— 全部来自浏览器真值, Python 复刻须逐字符一致
    "samples": [
        ("POST", "/rest/skills", 98253121, 60,
         "PMcFStekmZBXB8apLHqSg+f2nQGYblXDqARYKAF90GRgnLgkBzvhctN3RLSTYiy0An0F5zkxx3us+aMbj3kOrUQP1tgHPw"),
        ("GET", "/rest/user-skills", 98253121, 136,
         "iHOx/mMQLSTjs3IdmM4mN1NCKbUs2uF3HLDsnLXJZNDUKAyQs49VxmfD8AAn1pgAtsmxU423Hm3Yb4r6ounQ5/55eWskiw"),
        ("POST", "/rest/rate-limits", 98253121, 51,
         "M8gKRdirlp9YCMmmI3WdjOj5kg6XYVrMpwtXJw5y32tvk7crCDTufdx4S7ucbSO7DXIK6DZ3TVPpNYqNncFFvKcoiZL+MA"),
        ("POST", "/rest/models/imagine/overrides", 98253122, 90,
         "WqFjLLHC//YxYaDPShz05YGQ+2f+CDOlzmI+TmcbtgIG+t5CYV2HFLURItL1BErSZBhjgV84BeLUG5UeerQIdy5AkKHHWQ"),
        ("POST", "/rest/media/pipeline/template/list", 98253122, 66,
         "Qrl7NKna5+4pebjXUgTs/ZmI43/mECu91nomVn8Drhoe4sZaeUWfDK0JOsrtHFLKfAB7mUcmwquxiJrZnmV3vB6+fkYWQQ"),
        ("POST", "/rest/media/imagine/quota_info", 98253122, 66,
         "Qrl7NKna5+4pebjXUgTs/ZmI43/mECu91nomVn8Drhoe4sZaeUWfDK0JOsrtHFLKfAB7mUfg4EeVtttX2Yrr8d3fplNdQQ"),
        ("POST", "/rest/skills", 98253125, 81,
         "UapoJ7rJ9P06aqvEQRf/7oqb8Gz1AziuxWk1RWwQvQkN8dVJalaMH74aKdn+D0HZbxRoilSoH/h00mm3HrJGG1wenY86Ug"),
        ("GET", "/rest/user-skills", 98253125, 53,
         "Nc4MQ96tkJleDs+gJXObiu7/lAiRZ1zKoQ1RIQh02W1plbEtDjLoe9p+Tb2aayW9C3AM7jCJWqVcEVYaHOTshnm3UkBgNg"),
    ],
}


# 会话 D (2026-06-12 实测, 当前 build sentry-release 9d769be3…, z(Q) 正常工作):
#   - 首次在「真签名正常工作 (94 字符, 非 x0 兜底)」的当前 build 上完成全链验证。
#   - 抓取手法: 主世界注入 <script> hook crypto.subtle.digest (绕过 isolated world),
#     真实 UI 点击会话链接触发 grok 内部 client 发签名请求 -> 读明文输入取 SALT。
#   - 关键交叉验证: 先从页面网络层抓到一条真实 94 字符 x-statsig-id (页面自发),
#     反推内嵌 Q == 当前 meta Q (qMatch=true); 再用 hook 读到的 SALT 纯 Python 重算
#     该真签名 -> EXACT MATCH (tf=98271610, r=142)。即「真值 header」与「纯算」双向闭合。
#   - SALT 后缀 6bd574…: color 行 6bd574=rgb(107,213,116) 取自固定 m 矩阵;
#     transform matrix 数字 ≈ [0.8,0.6,-0.6,0.8,…] = rotate≈37° 旋转矩阵 (C 来自 Q)。
#     -> 印证「color 取固定 m 行 + transform 是 Q→C→旋转角」, 同一 build 不同 Q 出不同 SALT。
#   - 22 条 digest 调用跨 conversations_v2/subscriptions/skills 等端点 SALT 完全一致。
_SELF_TEST_D = {
    "q_b64": "7cAxqu5OvS7cl7K6DL0Key3vtpbSwToW0ilvtKwmk/sPDSKtTZRkTWDLdvjMLNUB",
    "salt": ("obfiowerehiring6bd5740ccccccccccccd0"
             "999999999999980999999999999980ccccccccccccd00"),
    # 这条 expected 是页面网络层抓到的真实 x-statsig-id (94 字符), 非构造:
    "samples": [
        ("GET", "/rest/app-chat/conversations", 98271610, 142,
         "jmNOvyRgwDOgUhk8NIIzhPWjYTgYXE+0mFyn4ToiqB11gYOsI8Ma6sPuRfh2QqJbj/QPVYsMnW08g+DvGEkYJ0lJ5ZXFjQ"),
    ],
}


def _self_test() -> bool:
    Q = base64.b64decode(_SELF_TEST["q_b64"])
    assert len(Q) == 48, f"Q len = {len(Q)}"
    got = gen_x_statsig_id(
        _SELF_TEST["method"],
        _SELF_TEST["pathname"],
        Q,
        _SELF_TEST["salt"],
        ts=_SELF_TEST["tf"] + BASE_EPOCH,
        r=_SELF_TEST["r"],
    )
    ok = got == _SELF_TEST["expected"]
    print("[core algo] ", "PASS" if ok else "FAIL")
    if not ok:
        print("  got     :", got)
        print("  expected:", _SELF_TEST["expected"])

    # SALT 纯复刻: 浏览器渲染指纹, 暂未实现 (见 compute_salt 说明)
    try:
        compute_salt(Q)
        print("[compute_salt] (unexpected: implemented)")
    except NotImplementedError:
        print("[compute_salt] N/A  (浏览器渲染指纹, 改用 ExtractedFingerprint)")

    # 提取式: 用已提取的 (Q, SALT) 纯 Python 签名 -> 复刻真实 header
    fp = ExtractedFingerprint(_SELF_TEST["q_b64"], _SELF_TEST["salt"])
    got2 = fp.sign(
        _SELF_TEST["method"],
        _SELF_TEST["pathname"],
        ts=_SELF_TEST["tf"] + BASE_EPOCH,
        r=_SELF_TEST["r"],
    )
    fp_ok = got2 == _SELF_TEST["expected"]
    print("[extracted ]", "PASS" if fp_ok else "FAIL", " (提取式签名复刻真实值)")

    # 降级兜底值: 官方前端 z() 抛错时发送的 x0 值 (2026-06-11 实测服务端 200 接受)
    fb_ok = official_fallback_value() == (
        "eDA6VHlwZUVycm9yOiBDYW5ub3QgcmVhZCBwcm9wZXJ0aWVzIG9mIHVuZGVm"
        "aW5lZCAocmVhZGluZyAnY2hpbGROb2Rlcycp"
    )
    print("[x0 fallback]", "PASS" if fb_ok else "FAIL", " (官方失败路径值, 服务端接受)")

    # 会话 C: 全新会话 (Q, SALT), 8 个端点真签名逐字符复刻 (跨多 method/r/tf)
    fp_c = ExtractedFingerprint(_SELF_TEST_C["q_b64"], _SELF_TEST_C["salt"])
    c_pass = 0
    for method, path, tf, r, expected in _SELF_TEST_C["samples"]:
        got_c = fp_c.sign(method, path, ts=tf + BASE_EPOCH, r=r)
        if got_c == expected:
            c_pass += 1
        else:
            print(f"  [C FAIL] {method} {path} tf={tf} r={r}")
            print(f"    got     : {got_c}")
            print(f"    expected: {expected}")
    n_c = len(_SELF_TEST_C["samples"])
    c_ok = c_pass == n_c
    print(f"[session C ]", "PASS" if c_ok else "FAIL",
          f" ({c_pass}/{n_c} 全新会话逐字符复刻)")

    # 会话 D: 当前 build (真签名正常工作), 复刻页面网络层抓到的真实 94 字符 header
    fp_d = ExtractedFingerprint(_SELF_TEST_D["q_b64"], _SELF_TEST_D["salt"])
    d_pass = 0
    for method, path, tf, r, expected in _SELF_TEST_D["samples"]:
        got_d = fp_d.sign(method, path, ts=tf + BASE_EPOCH, r=r)
        if got_d == expected:
            d_pass += 1
        else:
            print(f"  [D FAIL] {method} {path} tf={tf} r={r}")
            print(f"    got     : {got_d}")
            print(f"    expected: {expected}")
    n_d = len(_SELF_TEST_D["samples"])
    d_ok = d_pass == n_d
    print(f"[session D ]", "PASS" if d_ok else "FAIL",
          f" ({d_pass}/{n_d} 当前 build 真签名复刻, 与网络层真值闭合)")

    return ok and fp_ok and fb_ok and c_ok and d_ok


if __name__ == "__main__":
    _self_test()
