# grok.com `x-statsig-id` 字段生成过程详解

> 面向「想快速搞懂这个字段怎么来的」的讲解文档。
> 算法的完整逆向证据见 [`x-statsig-id-逆向分析.md`](./x-statsig-id-逆向分析.md)；
> 项目落地对比见 [`x-statsig-id-算法对比.md`](./x-statsig-id-算法对比.md)；
> 可运行参考实现 [`x_statsig_id.py`](./x_statsig_id.py) / 拼装层复刻 [`salt_assembly.py`](./salt_assembly.py)。
> 最后更新：2026-06-11

---

## 0. 一句话概括

`x-statsig-id` 是 grok.com 前端给**每个 API 请求**附带的签名头，本质是

```
base64( 随机头 + 设备指纹Q + 时间 + SHA256(方法!路径!时间+盐)[:16] + 尾常量 )   再整体异或随机头
```

其中「盐 SALT」由设备指纹 Q 经一段**浏览器 CSS 动画渲染指纹** `z(Q)` 派生。

---

## 1. 触发时机：fetch 中间件的两条分支

前端有个 fetch 拦截中间件 `ss`，拦下所有请求，在发出前注入签名头：

```
fetch(url, init)
  └─ ss(e)                                    // 拦截所有 fetch
       ├─ try:   t = await sl(pathname, method)   // 懒加载真签名函数（内部代号 botoxSign）
       ├─ catch: t = btoa("x0:" + error)          // 签名抛错时的兜底
       └─ headers.set("x-statsig-id", t)
          headers.set("x-xai-request-id", uuid)
```

- 正常 → 走 `try`，产出 94 字符**真签名**。
- `z(Q)` 渲染指纹抛错 → 走 `catch`，发送 `btoa("x0:" + 错误文本)` 兜底值。
- **本项目模仿的就是 catch 这条**（详见算法对比文档）。

---

## 2. 三个输入材料

签名需要三样东西：

### ① METHOD + pathname
当前请求的方法和路径（去掉 query），例如 `GET` + `/rest/app-chat/conversations`。

### ② Q —— 48 字节设备指纹
来自服务端 SSR 下发的 meta 标签：

```js
Q = atob( document.querySelector('meta[name="grok-site―verification"]').content )
```

- ⚠️ meta name 里的 `―` 是 **U+2015 全角横线**，不是普通连字符 `-`（刻意防 grep / 选择器命中）。
- content 是 48 字节的标准 base64（64 字符）。
- **存在于 SSR 原始 HTML 中** → 纯 HTTP `GET /` 即可抓，无需执行 JS。
- 每个 HTML 文档下发**不同的 Q**（每次页面加载绑定一个新指纹种子）。

### ③ SALT —— 由 Q 派生的渲染指纹

```
SALT = "obfiowerehiring" + z(Q)
```

- 前缀 `obfiowerehiring` 是代码里的字面常量（"obf io we're hiring" 招聘彩蛋）。
- `z(Q)` 是浏览器 CSS/Web-Animations 渲染指纹（见 §4）。
- **关键性质**：SALT 对固定 Q 确定（与时间/随机/会话无关），所以服务端能用其下发的 Q 重算校验。

---

## 3. 核心签名算法（纯 SHA-256，非 HMAC）

材料齐了，主算法很直白：

```python
# 1. 时间因子：秒级时间戳减去基准 2023-05-01T07:00:00Z
timeFactor = floor(now / 1000) - 1682924400

# 2. 拼字符串，SHA-256
message = f"{METHOD}!{pathname}!{timeFactor}{SALT}"
digest  = SHA256(message)                 # 32 字节

# 3. 随机头：每次调用随机 1 字节
r = floor(random() * 256)

# 4. 拼 70 字节 payload
payload = [r]                  # 1B  随机头
        + Q                    # 48B 设备指纹
        + uint32LE(timeFactor) # 4B  时间（小端）
        + digest[:16]          # 16B SHA-256 前半
        + [3]                  # 1B  尾常量 L=3

# 5. 混淆：除第 0 字节外，全部异或 r
out[0] = r
out[i] = payload[i] ^ r        # i >= 1

# 6. base64 去填充
x-statsig-id = base64(out).rstrip("=")     # 94 字符
```

### 字节布局（异或前的 payload，70B）

```
偏移   0      1 ───────────── 48     49 ── 52      53 ──────── 68    69
     ┌────┬───────────────────────┬────────────┬─────────────────┬──────┐
     │ r  │  Q  (设备指纹 48B)     │ tf uint32LE│ SHA256[:16] 16B │ L=3  │
     └────┴───────────────────────┴────────────┴─────────────────┴──────┘
       └─ 随机头；其余 69 字节输出时统一 XOR r（服务端取 out[0] 还原）
```

### 服务端如何校验

1. base64 解码 → 取 `out[0]` 当随机头 `r`。
2. 其余字节 `^ r` 还原 payload → 取出内嵌的 Q 和 timeFactor。
3. 用**自己 SSR 下发的 Q** 重算 `SALT = f(Q)`。
4. 重算 `SHA256("{M}!{path}!{tf}" + SALT)`，比对内嵌的前 16 字节。

→ 所以 **Q 和 SALT 不能乱填**，随机盐会失配。

> ✅ 此算法已用纯 Python 逐字符复刻浏览器真值：**三组独立会话**（B 1 样本 + C 8 样本 + D 1 样本）跨多端点/多随机头/多时间戳，**全部 EXACT MATCH**。其中会话 D（2026-06-12，当前 build `9d769be3…`）是先从网络层抓到页面**自发的真实 94 字符 header**、再用 hook 读到的 SALT 纯 Python 重算它——「真值」与「纯算」双向闭合（详见逆向分析文档 §2.5）。

---

## 4. 最复杂的 z(Q)：浏览器渲染指纹

`z(Q)` 产出 SALT 的 hex 后缀，本质是**用浏览器 CSS 动画引擎算指纹**：

```js
z(Q) = {
  // ① 从 Q 取几个字节决定参数（索引随 build 漂移）
  a = Q[22] % 16                            // 选颜色组
  C = (Q[14]%16 + Q[36]%16) - Q[33]%16      // 动画 currentTime

  // ② m = 从 .r-7ya3u 容器的 SVG <path d> 解析出的颜色/几何矩阵
  m = parse(".r-7ya3u 的 path d 属性)        // build 常量，与 Q 无关

  // ③ 建临时元素，跑动画到 currentTime=C
  el.animate( 由 m[a] 派生的 keyframes )
  anim.currentTime = g(C)

  // ④ 读插值后的 computed style
  cs = getComputedStyle(el)

  // ⑤ 提取 color+transform 里所有数字 → 浮点转 16 进制 → 去符号
  return ("" + cs.color + cs.transform)
            .match(/([\d.-]+)/g)
            .map(n => parseFloat(parseFloat(n).toFixed(2)).toString(16))   // ★ 关键拼装
            .join("").replace(/[.-]/g, "")
}
```

### 实例（会话 B，`Q[22]=52 → a=4`）

- 颜色 `m[4][:3] = [75,88,207]` → `rgb(75,88,207)` → `4b58cf`
- transform 平凡 `matrix(1,0,0,1,0,0)` → 数字 `1,0,0,1,0,0` → `100100`
- 拼出 z(Q) = `4b58cf100100`，SALT = `obfiowerehiring4b58cf100100`

### 最唬人的「拼装层」其实不玄学

会话 C 那串神秘的 `...28f5c28f5c28f6...` 一度被当成"无法纯算的渲染玄学"。真相是 JS 浮点转 16 进制：

```
(0.16).toString(16) = "0.28f5c28f6"     ← 去掉 "0." 即 "28f5c28f6..."
```

→ 已用纯 Python 复刻 V8 的 `Number.toString(16)` 浮点算法，B/C 两会话 SALT 后缀**逐字符 EXACT**（见 `salt_assembly.py`）。

### z(Q) 各步纯算可行性

| 步骤 | 内容 | 纯算可行性 |
|---|---|---|
| ① 字节选择 | `a=Q[i]%16`、`C=f(Q[j..])` | ✅ 纯算（但索引按 build 漂移） |
| ② **m 矩阵** | `.r-7ya3u` 的 SVG `<path d>` | ⚠️ **唯一非纯算输入**：运行时 React 挂载，不在 SSR HTML/不在签名 chunk |
| ③ color | 取 `m[a]` 整数 RGB 行 | ✅ 纯算（已有 m 时） |
| ④ transform | 动画 `currentTime=round(C/10)*10` 的 matrix 插值（cubic-bezier） | ✅✅ 已纯算复刻，与 Chrome 引擎逐位吻合（见下） |
| ⑤ 拼装 | `toFixed(2)→toString(16)→去符号` | ✅✅ 已逐字符复刻 |

> **④ 已正向闭合（2026-06-12）**：`currentTime` 公式解出为 `round(C/10)*10`（量化到 10ms 网格），动画 keyframes 由 `m[a]` 派生：`color=[#RGB(row[0:3]), #RGB(row[3:6])]`、`rotate(0→H(row[6],60,360))deg`、`easing=cubic-bezier(row[7:11] 经 H 映射)`。纯 Python 复刻 W3C cubic-bezier 求值 + 旋转 matrix 插值，输出与 Chrome Web-Animations computed matrix 在 ct∈{0,10,100,320,1000} 上**逐位吻合到 6 位小数**（含控制点 y 为负时的反向 overshoot）。端到端 `build_z_suffix(row,C)` 对 run1 平凡/非平凡向量均 EXACT。详见逆向文档 §5.2.3 与 `salt_assembly.py`。至此 z(Q) 全链仅剩 ② m 矩阵须每 build 取一次。

---

## 5. 离线落地的取舍

z(Q) 唯一离不开浏览器的是 **m 矩阵**（运行时图标 SVG path）。落地方案：

| 方案 | 做法 | 评价 |
|---|---|---|
| **A 提取式（推荐）** | 浏览器 hook `crypto.subtle.digest` 一次，读明文输入取 SALT；之后纯 Python 高频签名 | ✅ 立即可用、**天然抗 build 变化**（读的是当前代码实算的 SALT） |
| **B 查找表** | 预言机标定 ≤736 种 `(a,C)`→SALT 建表 | ⚠️ 按 build 绑定，发版即作废，不推荐 |
| **B′ 纯算 z(Q)** | 复刻整个 z(Q) | ⚠️ 可做但 m + 字节索引随发版漂移，维护成本高于 A |
| **兜底（当前项目）** | 直接发 `btoa("x0:" + error)` 假报错 | ✅ 当前 x-statsig-id 非硬闸门，服务端照常 200 |

### ⚠️ 运行时实测（2026-06-11）

- 官方前端的 `z(Q)` 在 CDP/自动化环境下自身就抛 `TypeError ...childNodes`（`.r-7ya3u` 元素缺失 → `undefined.childNodes`），前端**自己**就走 catch 发送 x0 兜底值。
- 服务端对各 `/rest/*` 端点**照常返回 200**。
- 推断：**x-statsig-id 现阶段更像「尽力而为的遥测/风控信号」而非硬闸门**。真正的反爬闸口是 `cf_clearance` + `sso` +（部分端点）`x-challenge` / `x-signature`。

---

## 6. 完整数据流图

```
                    ┌─────────────────────────────────────────┐
   GET /  (SSR) ───▶│ <meta name="grok-site―verification">     │
                    │   content (base64) ──atob──▶ Q (48B)     │
                    └─────────────────────────────────────────┘
                                    │
                  ┌─────────────────┴─────────────────┐
                  ▼                                     ▼
        ┌──────────────────┐               每个 API 请求触发 ss 中间件
        │  z(Q) 渲染指纹   │                         │
        │  (CSS动画+插值)  │                         ▼
        └────────┬─────────┘            timeFactor = floor(now/1000)-1682924400
                 ▼                                   │
   SALT = "obfiowerehiring" + z(Q)                   │
                 │                                   │
                 └──────────────┬────────────────────┘
                                ▼
        message = "{METHOD}!{pathname}!{timeFactor}" + SALT
                                │
                          SHA256(message)[:16]
                                │
        payload = [r] + Q + uint32LE(tf) + sha256[:16] + [3]   (70B)
                                │
                    out[i] = payload[i] ^ r   (i>=1)
                                │
                  base64(out).rstrip("=")   ──▶  x-statsig-id (94 字符)
```

---

## 7. 本机复现

```bash
cd docs/reverse

# 验证核心签名算法逐字符复刻浏览器真值
PYTHONUTF8=1 python x_statsig_id.py
# 预期：[core algo] PASS / [extracted] PASS / [x0 fallback] PASS / [session C] PASS (8/8)

# 验证 SALT 拼装层（Number.toString(16) 浮点）纯 Python 复刻
PYTHONUTF8=1 python salt_assembly.py
# 预期：① toString16 全 PASS / ⑤ 完整后缀拼装 session B/C 全 PASS
```
