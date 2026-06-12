"""x-statsig-id 生成 —— 真签名 + x0 兜底。

逆向结论与逐字符验证见 ``docs/reverse/x-statsig-id-逆向分析.md``。本模块把已验证
的纯 Python 算法落地到生产，按配置在两种形态间选择：

  - **真签名 (real)**：需一组会话指纹 ``(Q, SALT)``。算法 =
      ``SHA-256("{METHOD}!{pathname}!{timeFactor}" + SALT)`` 经编排 + XOR + base64，
      产出 94 字符。实测（2026-06）用一组指纹纯 Python 现场签名，可跨多账号发消息
      全部 200（创建真实会话），即服务端接受该签名。
  - **x0 兜底 (fallback)**：模仿官方前端 ``z(Q)`` 抛错时 fetch 中间件 catch 分支
      ``btoa("x0:" + error)``。当前 build 下官方自身即发此值、服务端仍 200。

指纹 ``(Q, SALT)`` 与 ``cf_clearance`` 同构：build 常量级别，grok 发新构建后失效、
需重新提取一次（浏览器读 ``meta[name="grok-site―verification"]`` 得 Q、hook
``crypto.subtle.digest`` 读明文输入取 SALT）。故默认行为是「配齐指纹走真签名，
缺失或异常自动回退 x0 兜底」——开箱即用，配齐即升级。
"""

import base64
import hashlib
import random
import re
import string
import struct
import time
from dataclasses import dataclass
from typing import Any, Optional

from app.platform.logging.logger import logger
from app.platform.config.snapshot import get_config


# ---------------------------------------------------------------------------
# 常量 (实测确认)
# ---------------------------------------------------------------------------
BASE_EPOCH = 1682924400          # 2023-05-01T07:00:00.000Z, 秒
SALT_PREFIX = "obfiowerehiring"  # 字面常量 ("obf io we're hiring" 招聘彩蛋)
TAIL_L = 3                       # 输出 payload 尾字节常量
Q_LEN = 48                       # Q 设备指纹字节数

# meta name 中间是 U+2015 (―) 全角横线, 不是普通 '-' (刻意防搜索/选择器)
_META_RE_NC = re.compile(
    r'<meta[^>]*name=["\']grok-site―verification["\'][^>]*content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_META_RE_CN = re.compile(
    r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']grok-site―verification["\']',
    re.IGNORECASE,
)

# 官方前端当前实际发送的静态 x0 兜底值 (base64):
#   = base64("x0:TypeError: Cannot read properties of undefined (reading 'childNodes')")
_OFFICIAL_X0_FALLBACK = (
    "eDA6VHlwZUVycm9yOiBDYW5ub3QgcmVhZCBwcm9wZXJ0aWVzIG9mIHVuZGVmaW5lZCAocmVhZGluZyAnY2hp"
    "bGROb2Rlcycp"
)


# ---------------------------------------------------------------------------
# Q (48 字节设备指纹) 提取
# ---------------------------------------------------------------------------
def extract_q_from_html(html: str) -> bytes:
    """从 SSR HTML 的 meta 标签提取并解码 48 字节 Q 指纹。"""
    m = _META_RE_NC.search(html) or _META_RE_CN.search(html)
    if not m:
        raise ValueError("未找到 grok-site―verification meta 标签")
    q = base64.b64decode(m.group(1))
    if len(q) != Q_LEN:
        raise ValueError(f"Q 长度异常: {len(q)}B (应为 {Q_LEN})")
    return q


# ---------------------------------------------------------------------------
# 核心: 真签名 (已逐字符验证, 见逆向文档 §2.4)
# ---------------------------------------------------------------------------
def gen_x_statsig_id(
    method: str,
    pathname: str,
    q: bytes,
    salt: str,
    ts: float | None = None,
    r: int | None = None,
) -> str:
    """生成 94 字符 x-statsig-id 真签名。

    给定相同 ts/r, 输出与浏览器逐字符一致。

    method   : HTTP 方法 (内部转大写)
    pathname : URL 路径 (去 query)
    q        : 48 字节设备指纹
    salt     : 完整 SALT (obfiowerehiring + z(Q))
    ts       : Unix 秒级时间戳 (默认当前时间)
    r        : 随机头字节 0-255 (默认随机)
    """
    if len(q) != Q_LEN:
        raise ValueError(f"Q 必须为 {Q_LEN} 字节")
    tf = int(ts if ts is not None else time.time()) - BASE_EPOCH
    msg = f"{method.upper()}!{pathname}!{tf}{salt}".encode()
    digest = hashlib.sha256(msg).digest()  # 32B
    if r is None:
        r = random.randrange(256)
    payload = bytes([r]) + q + struct.pack("<I", tf) + digest[:16] + bytes([TAIL_L])
    out = bytes([payload[0]] + [b ^ r for b in payload[1:]])
    return base64.b64encode(out).decode().rstrip("=")


# ---------------------------------------------------------------------------
# x0 兜底
# ---------------------------------------------------------------------------
def x0_fallback(dynamic: bool = False) -> str:
    """官方前端 z(Q) 抛错时的 x0 兜底值 (base64)。

    dynamic=True: 每次生成内容不同的 x0 兜底, 贴近"随机失败", 降低指纹一致性。
    dynamic=False: 逐字节对齐官方当前实际发送的静态值。
    """
    if not dynamic:
        return _OFFICIAL_X0_FALLBACK
    if random.choice((True, False)):
        rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=5))
        msg = f"x0:TypeError: Cannot read properties of null (reading 'children['{rand}']')"
    else:
        rand = "".join(random.choices(string.ascii_lowercase, k=10))
        msg = f"x0:TypeError: Cannot read properties of undefined (reading '{rand}')"
    return base64.b64encode(msg.encode()).decode()


# ---------------------------------------------------------------------------
# 配置解析: 全局单指纹 (与 cf_clearance 同构)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class StatsigFingerprint:
    """全局 statsig 指纹 (从 config [statsig] 段解析)。"""

    q: bytes | None = None
    salt: str = ""

    @property
    def is_complete(self) -> bool:
        return self.q is not None and len(self.q) == Q_LEN and bool(self.salt)


def _normalize_salt(salt: str) -> str:
    """容错: 允许只配 z(Q) 后缀, 自动补 obfiowerehiring 前缀。"""
    salt = salt.strip()
    if not salt:
        return ""
    return salt if salt.startswith(SALT_PREFIX) else SALT_PREFIX + salt


def resolve_statsig_fingerprint(cfg: Any | None = None) -> StatsigFingerprint:
    """从配置解析全局指纹。Q 配置为 48 字节的 base64, SALT 为完整或后缀。

    解析失败 (空/格式错/长度错) 返回不完整指纹 -> 上层自动回退 x0 兜底。
    """
    cfg = cfg or get_config()
    q_b64 = cfg.get_str("statsig.q", "").strip()
    salt = _normalize_salt(cfg.get_str("statsig.salt", ""))
    if not q_b64 or not salt:
        return StatsigFingerprint()
    try:
        q = base64.b64decode(q_b64)
    except Exception as exc:
        logger.warning("statsig.q base64 解码失败, 回退兜底: {}", exc)
        return StatsigFingerprint()
    if len(q) != Q_LEN:
        logger.warning("statsig.q 长度异常 {}B (应为 {}), 回退兜底", len(q), Q_LEN)
        return StatsigFingerprint()
    return StatsigFingerprint(q=q, salt=salt)


# ---------------------------------------------------------------------------
# 顶层入口: 按配置选真签名 / 兜底
# ---------------------------------------------------------------------------
def statsig_id(method: Optional[str] = None, pathname: Optional[str] = None) -> str:
    """生成 x-statsig-id 头值。

    优先真签名 (需 [statsig] 配齐指纹 + 提供 method/pathname); 任一前提不满足
    或签名异常时, 自动回退 x0 兜底 (是否动态由 features.dynamic_statsig 控制)。

    调用方在能提供请求上下文时应传 method/pathname; 不传则强制走兜底。
    """
    cfg = get_config()
    mode = cfg.get_str("statsig.mode", "real").strip().lower()
    dynamic_fb = cfg.get_bool("features.dynamic_statsig", False)

    if mode != "fallback" and method and pathname:
        fp = resolve_statsig_fingerprint(cfg)
        if fp.is_complete:
            try:
                sig = gen_x_statsig_id(method, pathname, fp.q, fp.salt)
                logger.debug(
                    "statsig 真签名: method={} pathname={} len={}",
                    method,
                    pathname,
                    len(sig),
                )
                return sig
            except Exception as exc:
                logger.warning("statsig 真签名失败, 回退 x0 兜底: {}", exc)

    logger.debug(
        "statsig x0 兜底: mode={} method={} pathname={}", mode, method, pathname
    )
    return x0_fallback(dynamic_fb)


__all__ = [
    "BASE_EPOCH",
    "SALT_PREFIX",
    "Q_LEN",
    "extract_q_from_html",
    "gen_x_statsig_id",
    "x0_fallback",
    "StatsigFingerprint",
    "resolve_statsig_fingerprint",
    "statsig_id",
]
