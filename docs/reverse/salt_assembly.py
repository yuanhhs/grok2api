r"""
SALT 拼装层破解 —— z(Q) 最后一步 "Number → toString(16)" 的纯 Python 复刻。

配套: docs/reverse/x-statsig-id-逆向分析.md §5.2 / §5.2.2

背景:
  此前文档判定 z(Q) "纯 Python 复刻不现实"(认为 color/transform 是浏览器
  Web-Animations 活体插值玄学)。2026-06-11 把签名 chunk 去混淆到原语级后,
  发现最唬人的那串 "...28f5c28f5c28f6..." **不是玄学**,而是 JS 的
  `Number.prototype.toString(16)` 浮点输出:
      (0.16).toString(16) === "0.28f5c28f6"   ← 去掉 "0." 即 "28f5c28f6..."

  z(Q) 去混淆后最后一步(变量名还原):
      A = Array.from(("" + cs.color + cs.transform).match(/([\d.-]+)/g))
            .map(n => parseFloat(parseFloat(n).toFixed(2)).toString(16))
            .join("")
            .replace(/[.-]/g, "")     // 去掉所有小数点和负号
  即: 把 computed color+transform 里的每个数字,
      ① 先 toFixed(2) 截断到 2 位小数 -> parseFloat
      ② 再 Number.toString(16) 转 16 进制(浮点!不是整数)
      ③ 拼接后删除所有 '.' 和 '-'

  本文件纯 Python 复刻 ② 这一步(V8/SpiderMonkey 的 Number.toString(16)),
  对照浏览器/Node 已知真值,证明 "拼装层" 完全可纯算。

⚠️ 诚实边界(哪些已破 / 哪些仍需浏览器):
  ┌─ z(Q) 全链 ────────────────────────────────────────────────────────┐
  │ ① 字节选择 a=Q[i]%16, C=f(Q[j..])  : ✅ 纯算 (但索引按 build 漂移)    │
  │ ② m 颜色/几何矩阵 = .r-7ya3u 的 SVG <path d> 解析                    │
  │      = build 常量(与 Q 无关), 但 **不在 SSR HTML / 不在签名 chunk**,│
  │        是运行时 React 挂载的图标元素 -> 仍须浏览器渲染提取一次/每build │
  │      (本会话实测: SSR HTML 有 meta(Q) 但 svg/path=0、无 .r-7ya3u)    │
  │ ③ color = m[a] 在 currentTime 处的 RGB 插值 (起点 row[0:3]->row[3:6]) │
  │      : ✅ 纯算 (前提是已有 m; ct=0 时退化为起点整数 rgb)              │
  │ ④ transform = 动画在 currentTime 的 matrix 插值 (cubic-bezier)       │
  │      : ✅✅ 本文件正向闭合 —— currentTime=round(C/10)*10,             │
  │        cubic-bezier(含负 overshoot) + rotate->matrix[cos,sin,-sin,..],│
  │        纯 Python forward 与 Chrome computed matrix 在 ct∈{0,10,20,    │
  │        30,100,320,1000} 逐位吻合到 6 位小数; 非平凡向量逐字符闭合     │
  │ ⑤ 拼装 toFixed(2)->toString(16)->去符号                              │
  │      : ✅✅ 本文件证明完全纯算                                         │
  └────────────────────────────────────────────────────────────────────┘

  ⭐ currentTime 公式破解关键(本会话):静态去混淆曾误把中层算子 vWSpQ 当
     乘法,实为函数调用 n(W)。正解 currentTime = hGLGR(vWSpQ(M, dFXaJ(C,10)),10)
     = round(C/10)*10。run1(C=1)->ct=0 平凡矩阵 100100,逐字符闭合证明公式正确。

结论(对"是否只能从浏览器获取"的精确回答):
  - SALT 的**算法**不再是黑盒: ①③④⑤ 全部确定计算, ④⑤ 已纯 Python 闭合。
  - 唯一非纯算输入是 **m 矩阵**(运行时 SVG 图标 path)。它是 build 常量,
    => 纯算路线 B′ 从"每会话开浏览器"降级到"每 build 提取一次 m + 标定字节索引"。
  - 但 ②(m 提取)+ ①索引 都按 build 漂移, 维护成本仍高于档次 A
    (每会话 hook crypto.subtle.digest 直接读明文 SALT, 天然抗 build)。
  => 生产仍推荐档次 A; 但"必须靠浏览器活体插值、纯算根本不可能"的旧判断被推翻。
"""
from __future__ import annotations

import math
import struct


# ---------------------------------------------------------------------------
# 复刻 JS Number.prototype.toString(16) —— 含小数部分的浮点 16 进制
# ---------------------------------------------------------------------------
# V8/SpiderMonkey 对带小数的 Number.toString(radix) 用的是 "足够区分相邻 double"
# 的最短表示算法(dtoa 的 radix 变体)。对 toFixed(2) 截断后的值(分母为 100 的
# 有限小数), 实测固定输出 ~13-14 位 16 进制小数, 末位不四舍五入而是截断到能
# 唯一还原 double 的精度。下面用"逐位提取 + double 往返校验"复刻该行为。
def js_number_to_string16(x: float) -> str:
    """复刻 JS 的 (x).toString(16)。x 已是 parseFloat(toFixed(2)) 的结果。"""
    if x == 0:
        return "0"
    neg = x < 0
    x = abs(x)

    int_part = int(x)
    frac = x - int_part

    # 整数部分: 标准 16 进制
    int_hex = format(int_part, "x") if int_part else "0"

    if frac == 0:
        return ("-" if neg else "") + int_hex

    # 小数部分: 逐位 *16 取整, 直到 "把已输出的 16 进制串解析回 double" == 原 double。
    # 这复刻了 V8 "最短可往返" 的停止条件。
    digits = []
    HEXCH = "0123456789abcdef"
    target = struct.unpack("<d", struct.pack("<d", x))[0]  # 规范化为 double
    f = frac
    for _ in range(30):  # double 的 16 进制小数最多 ~13-14 位, 30 足够
        f *= 16
        d = int(f)
        digits.append(d)
        f -= d
        # 往返校验: 当前 int_part + 已累计小数 hex 能否还原 target
        candidate = int_part
        scale = 1.0
        for dd in digits:
            scale /= 16.0
            candidate += dd * scale
        if struct.unpack("<d", struct.pack("<d", candidate))[0] == target:
            break
        if f == 0:
            break

    frac_hex = "".join(HEXCH[d] for d in digits)
    return ("-" if neg else "") + int_hex + "." + frac_hex


def assemble_token(n: float) -> str:
    """单个数字的拼装: parseFloat(toFixed(2)) -> toString(16) -> 去 '.' 和 '-'。"""
    # toFixed(2): 四舍五入到 2 位小数 (JS toFixed 用银行家舍入的近似, 这里用 round)
    fixed = float(f"{n:.2f}")
    return js_number_to_string16(fixed).replace(".", "").replace("-", "")


# ---------------------------------------------------------------------------
# ④ transform 插值 —— 纯 Python 复刻 W3C cubic-bezier easing + rotate matrix
# ---------------------------------------------------------------------------
# 2026-06-12 突破: ④ 不再是"必须靠浏览器活体插值"的黑盒。
# z 的动画构造(来自 body_cur.js 去混淆):
#   A(row) = {
#     color:    ["#"+RGB(row[0:3]), "#"+RGB(row[3:6])],
#     transform:["rotate(0deg)", "rotate(" + H(row[6],60,360,True) + "deg)"],
#     easing:   "cubic-bezier(" + [H(v, -1 if i%2 else 0, 1) for i,v in row[7:]] + ")",
#   }
#   H(n,t,r,c) = u=(n*(r-t))/255+t ;  floor(u) if c else round(u,2)
#   E: W = el.animate(A(row), dur=4096); W.pause(); W.currentTime = round(C/10)*10
#      再读 getComputedStyle(el).color / .transform
#
# currentTime 公式(本会话彻底解对 op-key, 见文档 §5.2.3):
#   currentTime = hGLGR(vWSpQ(M, dFXaJ(C,10)), 10) = round(C/10) * 10
#   注意 vWSpQ = 函数调用 n(W) 不是乘法; M = Math.round。
#   => C=1 -> 0ms ; C=6 -> 10ms ; C=15/20 -> 20ms ; C=30 -> 30ms
#
# 时间分数 x = currentTime / 4096, 经 cubic-bezier 映射成值进度 p(可为负:overshoot),
# 再线性插值 color 通道 / rotate 角度, rotate 角 -> 2D matrix [cos,sin,-sin,cos,0,0]。
#
# 验证强度: 纯 Python forward 的 matrix 与 Chrome Web-Animations computed matrix
#   在 ct∈{0,10,20,30,100,320,1000} 上逐位吻合到 6 位小数(本会话浏览器实测)。
ANIM_DURATION = 4096  # build 常量 y = 2 ** (4*3)


def js_round(x: float) -> int:
    """复刻 JS Math.round: round-half-up(向 +∞ 取半), 区别于 Python 的银行家舍入。

    JS: Math.round(0.5)=1, Math.round(-0.5)=0, Math.round(2.5)=3。
    Python round(0.5)=0(round-half-to-even), 必须修正, 否则 ct/color 偶发差 1。
    """
    return math.floor(x + 0.5)


def H(n: float, t: float, r: float, c: bool) -> float:
    """z 的插值映射 H=(n,t,r,c)=> u=(n*(r-t))/255+t; c?floor(u):+u.toFixed(2)。"""
    u = (n * (r - t)) / 255 + t
    return math.floor(u) if c else float(f"{u:.2f}")


def cubic_bezier_easing(x1: float, y1: float, x2: float, y2: float):
    """复刻 Chrome/W3C 的 cubic-bezier easing。

    控制点 (x1,y1)(x2,y2), 端点固定 (0,0)(1,1)。
    返回 f(x): 给动画时间分数 x∈[0,1], 先牛顿迭代解 t 使 bezierX(t)=x,
    再返回 bezierY(t)(值进度, 可超出 [0,1] 即 overshoot)。
    """
    NEWTON_ITER = 8
    SUBDIV_ITER = 12
    SUBDIV_EPS = 1e-7

    def _a(a: float, b: float) -> float:
        return 1.0 - 3.0 * b + 3.0 * a

    def _b(a: float, b: float) -> float:
        return 3.0 * b - 6.0 * a

    def _c(a: float) -> float:
        return 3.0 * a

    def calc(t: float, a: float, b: float) -> float:
        return ((_a(a, b) * t + _b(a, b)) * t + _c(a)) * t

    def slope(t: float, a: float, b: float) -> float:
        return 3.0 * _a(a, b) * t * t + 2.0 * _b(a, b) * t + _c(a)

    def t_for_x(x: float) -> float:
        t = x
        for _ in range(NEWTON_ITER):
            s = slope(t, x1, x2)
            if s == 0.0:
                break
            xv = calc(t, x1, x2) - x
            t -= xv / s
        # 二分兜底
        lo, hi, tt = 0.0, 1.0, x
        if t < lo:
            t = lo
        if t > hi:
            t = hi
        for _ in range(SUBDIV_ITER):
            xv = calc(tt, x1, x2)
            if abs(xv - x) < SUBDIV_EPS:
                return tt
            if xv < x:
                lo = tt
            else:
                hi = tt
            tt = (lo + hi) / 2.0
        return t

    def f(x: float) -> float:
        if x1 == y1 and x2 == y2:
            return x  # linear
        return calc(t_for_x(x), y1, y2)

    return f


def transform_progress(row: list[int], c_val: int) -> tuple[list[int], list[float]]:
    """正向算 (color_rgb, matrix6) —— ④ 的核心。

    row : m[a] 整数行(11 个 0-255)。
    c_val: 动画驱动 C = (Q[9]%16 + Q[36]%16) - Q[30]%16。
    返回 (插值后的整数 RGB[3], CSS matrix 6 元 [a,b,c,d,e,f])。
    """
    # easing 四个控制点: row[7:11], H(v, -1 if i%2 else 0, 1)
    easing = [H(v, -1 if i % 2 else 0, 1, False) for i, v in enumerate(row[7:11])]
    x1, y1, x2, y2 = easing
    rotate_to = H(row[6], 60, 360, True)  # 整数 deg

    current_time = js_round(c_val / 10) * 10  # ← currentTime 公式 (JS Math.round)
    x_frac = current_time / ANIM_DURATION
    p = cubic_bezier_easing(x1, y1, x2, y2)(x_frac)  # 值进度(可为负)

    # color: 起点 row[0:3] -> 终点 row[3:6], 线性插值后 round (JS Math.round)
    col = [js_round(row[i] + (row[i + 3] - row[i]) * p) for i in range(3)]

    # transform: rotate(rotate_to * p) -> 2D 旋转矩阵
    deg = rotate_to * p
    rad = deg * math.pi / 180.0
    cos_v, sin_v = math.cos(rad), math.sin(rad)
    matrix = [cos_v, sin_v, -sin_v, cos_v, 0.0, 0.0]
    return col, matrix


def build_z_suffix(row: list[int], c_val: int) -> str:
    """④ 全链正向: row + C -> z(Q) 的 SALT 后缀(纯 Python, 不碰浏览器)。

    复刻 z 末步:
      nums = [color r,g,b] + [matrix a,b,c,d,e,f]   (从 computed style 提取的数字序列)
      suffix = "".join(toString16(toFixed2(n)) for n in nums).replace(/[.-]/g,"")
    """
    col, matrix = transform_progress(row, c_val)
    nums = [float(v) for v in col] + list(matrix)
    return "".join(assemble_token(n) for n in nums)


# ---------------------------------------------------------------------------
# 已知真值对照 (来自浏览器/Node 实测, 见文档 §5.2)
# ---------------------------------------------------------------------------
# 格式: (输入数字, 期望 (n).toString(16))
_TOSTRING16_VECTORS = [
    (0.0, "0"),
    (1.0, "1"),
    (2.0, "2"),
    (0.5, "0.8"),
    (0.16, "0.28f5c28f5c28f6"),
    (-0.16, "-0.28f5c28f5c28f6"),
    (0.98, "0.fae147ae147ae"),
    (0.99, "0.fd70a3d70a3d7"),
]

# 完整后缀复刻: 给定 color 整数 RGB + transform 在 currentTime 处的 matrix 数字序列,
# 拼装出 z(Q) 后缀, 与真实 SALT 后缀逐字符比对。
# 注: 这里 color 行(m[a])与 transform matrix 数字均为该会话实测值(transform 数字
#     从真实 computed matrix 提取); 本向量证明的是"拼装层", 不含插值复刻。
_ASSEMBLY_VECTORS = [
    {
        "name": "session B",
        # m[4][:6] 两个颜色(只用前 3 进 color hex? 实测 color 只输出第一个 #rgb 的 6 hex)
        "color_rgb": [75, 88, 207],          # -> 4b58cf
        "transform_numbers": [1, 0, 0, 1, 0, 0],   # matrix(1,0,0,1,0,0) 平凡
        "expected": "4b58cf100100",
    },
    {
        "name": "session C",
        "color_rgb": [34, 70, 191],          # -> 2246bf
        # 真实 computed transform 提取的数字(从真 SALT 逐 token 反解校验):
        #   1·0·0.16·0·0.16·1·0·0 -> 1 0 028f5c28f5c28f6 0 028f5c28f5c28f6 1 0 0
        "transform_numbers": [1, 0, 0.16, 0, 0.16, 1, 0, 0],
        "expected": "2246bf10028f5c28f5c28f60028f5c28f5c28f6100",
    },
]


# ④ transform 插值正向闭合向量(纯 row+C -> suffix, 不碰浏览器)。
# 数据来自本会话浏览器实测: 用 z 真实 easing/duration 在 ct=round(C/10)*10 处的
#   computed color+matrix, 走 z 末步拼装得到 expected。我的纯 Python forward 的
#   matrix 已与 Chrome computed matrix 在 ct∈{0,10,20,30,100,320,1000} 逐位吻合。
#
# row = m[a] 整数行; C = (Q[9]%16+Q[36]%16)-Q[30]%16。
_INTERP_VECTORS = [
    {
        # golden_run1: Q[..]->a=3,C=1; m[3]=[221,181,84,...]; ct=round(0.1)*10=0
        # ct=0 -> p=0 -> color=起点 ddb554, matrix=单位 -> 100100
        "name": "run1 C=1 (ct=0 平凡)",
        "row": [221, 181, 84, 119, 84, 7, 89, 182, 73, 226, 187],
        "C": 1,
        "expected": "ddb554100100",
    },
    {
        # 同 row, C=15 -> ct=round(1.5)*10=20 -> 非平凡 matrix:
        #   sin=0.0084 -toFixed(2)-> 0.01 -toString(16)-> 028f5c28f6
        # 真正考验 cubic-bezier(0.71,-0.43,0.89,0.47) 的 overshoot 数学。
        "name": "run1 C=15 (ct=20 非平凡 bezier)",
        "row": [221, 181, 84, 119, 84, 7, 89, 182, 73, 226, 187],
        "C": 15,
        "expected": "ddb55410028f5c28f5c28f60028f5c28f5c28f6100",
    },
    {
        # 同 row, C=30 -> ct=round(3)*10=30 -> sin=0.0126 -toFixed(2)-> 0.01 同上
        "name": "run1 C=30 (ct=30)",
        "row": [221, 181, 84, 119, 84, 7, 89, 182, 73, 226, 187],
        "C": 30,
        "expected": "ddb55410028f5c28f5c28f60028f5c28f5c28f6100",
    },
]


def _rgb_to_hex(rgb: list[int]) -> str:
    return "".join(f"{v:02x}" for v in rgb)


def _self_test() -> bool:
    ok = True

    print("=== ① Number.toString(16) 浮点复刻 (对照浏览器真值) ===")
    for n, expected in _TOSTRING16_VECTORS:
        got = js_number_to_string16(float(f"{n:.2f}") if n else 0.0)
        # 对照: toFixed(2) 后再转, 但向量里的 expected 是直接 (n).toString(16)
        got_direct = js_number_to_string16(n)
        match = got_direct == expected
        ok &= match
        print(f"  ({n}).toString(16) = {got_direct!r}  {'PASS' if match else 'FAIL want '+expected!r}")

    print("\n=== ⑤ 完整后缀拼装 (color 整数行 + transform matrix 数字) ===")
    for v in _ASSEMBLY_VECTORS:
        color_hex = _rgb_to_hex(v["color_rgb"])
        trans_hex = "".join(assemble_token(x) for x in v["transform_numbers"])
        got = color_hex + trans_hex
        match = got == v["expected"]
        ok &= match
        print(f"  {v['name']}: {'PASS' if match else 'FAIL'}")
        if not match:
            print(f"    got : {got}")
            print(f"    want: {v['expected']}")

    print("\n=== ④ transform 插值正向闭合 (row + C -> suffix, 纯算) ===")
    for v in _INTERP_VECTORS:
        got = build_z_suffix(v["row"], v["C"])
        match = got == v["expected"]
        ok &= match
        print(f"  {v['name']}: {'PASS' if match else 'FAIL'}")
        if not match:
            print(f"    got : {got}")
            print(f"    want: {v['expected']}")

    print("\n[结论] z(Q) 末三层(③color 插值 / ④transform cubic-bezier 矩阵 / ⑤浮点拼装)"
          "纯 Python 复刻:", "全部 PASS" if ok else "有 FAIL")
    return ok


if __name__ == "__main__":
    _self_test()
