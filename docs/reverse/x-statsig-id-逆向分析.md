# grok.com `x-statsig-id` 逆向分析记录

> 目标：还原 grok.com 前端生成请求头 `x-statsig-id` 的完整真实算法。
> 方法：JSReverser-MCP（基于 Chrome DevTools Protocol）+ 代理 `127.0.0.1:7897`，真机浏览器动态调试。
> 状态：**✅ 已完全还原，并端到端验证通过**（Python 从零重算，逐字符复刻浏览器真实值）。
> Q 来源已定位（SSR meta，HTTP 可抓）；SALT 机制已完全揭示 = 浏览器 CSS/Web-Animations 渲染指纹，对固定 Q 确定。**z(Q) 仅依赖 Q 的 4 个字节（`Q[22]/[14]/[36]/[33]`，各先 `%16`），全部 SALT ≤736 种可枚举建查找表**（见 §5.2.1）→ 落地可用「提取式」或「标定→查找表」两条路线。Python 参考实现：[`x_statsig_id.py`](./x_statsig_id.py)。
> 最后更新：2026-06-11

---

## 0. TL;DR（最终结论）

| 项目 | 结论 | 置信度 |
|------|------|--------|
| 触发位置 | fetch 拦截中间件 `ss` → `sl(pathname, method)` 懒加载签名函数 | ✅ 确定 |
| 内部代号 | **botoxSign** | ✅ 确定 |
| 加密原语 | **`SHA-256`**（`crypto.subtle.digest("sha-256", …)`，**非** HMAC） | ✅ 实测 3/3 |
| 哈希输入 | **`"{METHOD}!{pathname}!{timeFactor}" + SALT`**（拼成一个字符串，UTF-8 编码） | ✅ 实测确认 |
| timeFactor | `floor(Date.now()/1000) − 1682924400`（基准 = **2023-05-01T07:00:00Z**） | ✅ 实测确认 |
| 输出长度 | 固定 **70 字节** → base64（去 `=`，94 字符） | ✅ 确定 |
| 输出布局 | `[r(1)] + Q(48) + uint32LE(timeFactor)(4) + SHA256[:16](16) + [L=3](1)` | ✅ 实测确认 |
| 混淆层 | 末字节起整体 **XOR 随机头 `r`**：`out[i]=payload[i]^r (i≥1)`，`out[0]=r` | ✅ 实测确认 |
| 非确定性来源 | 随机头 `r = floor(Math.random()*256)`，每次调用不同 | ✅ 确定 |
| 端到端复刻 | **Python `hashlib.sha256` 逐字符复刻真实 header 成功**；三组独立会话 B(1)+C(8/8)+D(当前 build 真签名) 全 EXACT | ✅ EXACT MATCH |
| Q (48B 指纹) | **= `atob(<meta name="grok-site―verification">.content)`**，服务端 SSR 下发，每个 HTML 文档不同 → **Python 可 HTTP 直接抓** | ✅ 已定位 |
| SALT | = `obfiowerehiring` + `z(Q)`；`z(Q)` = 从 SVG 图标 `<path d>` 取矩阵 `m`（旧 build `.r-7ya3u`、当前 build `.r-6wnaj0`）→ 动画 `currentTime=round(C/10)*10` 插值 color/transform → 拼装 | ✅ **z(Q) 全链 ①③④⑤ 已纯 Python 逐字符闭合**（④ cubic-bezier 插值与 Chrome 引擎逐位一致，§5.2.2 / §5.2.3）；唯一非纯算输入只剩 `m`（运行时 SVG，须每 build 取一次） |
| 失败 fallback | `btoa("x0:" + error)`；`z(Q)` 抛错时走此分支 | ✅ 确定 |
| ⚠️ 运行时实测 | **z(Q) 行为随 build 变化**：旧构建（sentry-release 4dc4856…）`z(Q)` 抛 `TypeError …childNodes` → 前端自发 x0 兜底（§5.4）；当前构建（9d769be3…）`z(Q)` **正常工作、发 94 字符真签名**（§5.4.1）。两种形态服务端对各 `/rest/*` 端点均返回 200 | ✅ 实测（见 §5.4 / §5.4.1 / §2.5） |

---

## 1. 完整算法（已验证）

### 1.1 伪代码

```
输入: METHOD（大写，如 "GET"/"POST"）, pathname（URL 路径，去 query）
会话常量: Q（48 字节数组）, SALT（字符串）

timeFactor = floor(Date.now()/1000) - 1682924400          // 秒级，uint32
message    = METHOD + "!" + pathname + "!" + timeFactor + SALT
digest     = SHA256( UTF8(message) )                       // 32 字节
r          = floor(Math.random() * 256)                    // 1 字节随机头

payload = [r]
        + Q                              // 48 字节（设备指纹）
        + uint32_little_endian(timeFactor)   // 4 字节
        + digest[0:16]                   // SHA-256 前 16 字节
        + [3]                            // 1 字节尾 (常量 L=3)
// 合计 1 + 48 + 4 + 16 + 1 = 70 字节

// 混淆：除第 0 字节(随机头)外，全部异或 r
out[0] = r
for i in 1..69: out[i] = payload[i] XOR r

x-statsig-id = base64(out).replace("=", "")               // 94 字符
```

### 1.2 字节布局（70 字节，异或前的 payload）

```
偏移   0      1 ───────────── 48     49 ── 52      53 ──────── 68    69
     ┌────┬───────────────────────┬────────────┬─────────────────┬──────┐
     │ r  │  Q  (设备指纹 48B)     │ tf uint32LE│ SHA256[:16] 16B │ L=3  │
     └────┴───────────────────────┴────────────┴─────────────────┴──────┘
       │                                                                  
       └─ 随机头；其余 69 字节在输出时统一 XOR r（服务端取 out[0] 还原）
```

### 1.3 Python 参考实现（已验证可逐字符复刻）

```python
import base64, struct, hashlib, random

BASE_EPOCH = 1682924400  # 2023-05-01T07:00:00Z

def gen_x_statsig_id(method: str, pathname: str, Q: bytes, salt: str,
                     ts: float | None = None, r: int | None = None) -> str:
    import time
    tf = int((ts if ts is not None else time.time())) - BASE_EPOCH
    msg = f"{method.upper()}!{pathname}!{tf}{salt}".encode()
    digest = hashlib.sha256(msg).digest()                 # 32B
    if r is None:
        r = random.randrange(256)
    payload = bytes([r]) + Q + struct.pack("<I", tf) + digest[:16] + bytes([3])
    out = bytes([payload[0]] + [b ^ r for b in payload[1:]])
    return base64.b64encode(out).decode().rstrip("=")
```

> **前提**：需要该会话的 `Q`(48B) 与 `salt`。给定相同的 `r`/`ts`，输出与浏览器**完全一致**（见 §2）。
> `Q` 与 `salt` 是会话级设备指纹（见 §5），是当前离线复刻的唯一未决变量。

---

## 2. 端到端验证证据

### 2.1 SHA-256 原语验证（3/3 MATCH）

用 preload hook 拦截 `crypto.subtle.digest`，捕获真实哈希输入/输出，Python `hashlib.sha256` 比对：

| 哈希输入 | sha256[:8] vs 浏览器输出[:8] |
|----------|------------------------------|
| `GET!/rest/app-chat/conversations!98185915obfiowerehiring4b58cf100100` | `[85,216,144,247,41,24,226,6]` ✅ |
| `GET!/rest/workspaces!98185915obfiowerehiring4b58cf100100` | `[89,150,75,39,28,40,53,78]` ✅ |
| `POST!/rest/skills!98185915obfiowerehiring4b58cf100100` | `[76,229,255,246,118,27,120,119]` ✅ |

### 2.2 70 字节布局验证（全段 MATCH）

真实样本 `GET /rest/app-chat/conversations`：
```
x-statsig-id = Gx28gG6f2+PaqUHLU9WAcz4VE78KEisvUfRcvCYG50UPLWPFuVsrDFFhOAd1B2vfMqApwR5Ow4vsMgP5Hdo011QuVOHqGA
```
base64 解码 70 字节 → 取 `r=out[0]=27` → 逐字节 `^r` 还原 payload：

| 段 | 还原值 | 校验 |
|----|--------|------|
| time_bytes (49-52) | `[187,50,218,5]` | == `uint32LE(98185915)` ✅ MATCH |
| sig_seg (53-68) | `[85,216,144,247,…,250,241]` | == `SHA256(msg)[0:16]` ✅ MATCH |
| tail L (69) | `3` | == 3 ✅ MATCH |
| Q (1-48) | `[6,167,155,117,…,196,41]` | = 会话指纹（见 §5） |

### 2.3 端到端逐字符复刻（EXACT MATCH）

给定 `Q`(反推) + `SALT` + `tf=98185915` + `r=27`，Python `gen_x_statsig_id` 重算：
```
reproduced: Gx28gG6f2+PaqUHLU9WAcz4VE78KEisvUfRcvCYG50UPLWPFuVsrDFFhOAd1B2vfMqApwR5Ow4vsMgP5Hdo011QuVOHqGA
real      : Gx28gG6f2+PaqUHLU9WAcz4VE78KEisvUfRcvCYG50UPLWPFuVsrDFFhOAd1B2vfMqApwR5Ow4vsMgP5Hdo011QuVOHqGA
>>> EXACT MATCH
```

### 2.4 第二组独立会话验证（会话 C，2026-06-11，8/8 EXACT MATCH）

> 用户手动过 Cloudflare 人机验证后，z(Q) 在真实浏览器环境**正常工作**（不再走 x0 兜底），借此采集了一组全新会话的真签名做二次端到端验证。

- **会话 C 指纹**（实测提取）：
  ```
  Q    = +zl265ilrGs7+pUQRq6/28qhPaRSaf+UOGQUPUHsWFyghBg7B91O70t4iK9eEIg+
  SALT = obfiowerehiring2246bf10028f5c28f5c28f60028f5c28f5c28f6100   ← 42 hex（含非平凡 transform，比会话 B 的 12 hex 长）
  ```
- **SALT 提取手法**：hook `crypto.subtle.digest`，读其明文输入 `"{METHOD}!{path}!{tf}{SALT}"`——SALT 直接肉眼可读，无需反推。
- **三层验证全部通过**：

  | 验证层 | 方法 | 结果 |
  |--------|------|------|
  | SHA-256 原语 | 同一 digest 调用内原子配对 `sha256(inText)==outHex` | **4/4 MATCH** |
  | 整串逐字符复刻 | 内容配对（内嵌 sig16 ↔ digest）后 Python 重建 | **8/8 EXACT** |
  | Q 提取正确性 | 解出的内嵌 Q vs meta Q | **8/8 True** |

- **8 个样本**跨 5 个端点、不同随机头 `r`（60/136/51/90/66/81/53…）、连续 3 个时间戳（tf 98253121→98253125），`gen_x_statsig_id` 全部逐字符一致。
- **关键旁证**：tf 推进期间 SALT **恒定不变** → 再次坐实「SALT 只依赖 Q」。
- 样本与可复现自测已固化进 [`x_statsig_id.py`](./x_statsig_id.py) 的 `_SELF_TEST_C`（运行 `python x_statsig_id.py` 见 `[session C ] PASS (8/8)`）。

### 2.5 第三组独立会话验证（会话 D，2026-06-12，当前 build，真值↔纯算双向闭合）

> **首次在「真签名正常工作」的当前 build（sentry-release `9d769be3…`）上完成全链验证。** 与会话 C 不同，这次不是事后构造，而是先从**网络层抓到一条页面自发的真实 94 字符 header**，再用 hook 读到的 SALT 纯 Python 重算它——「真值」与「纯算」从两端闭合。

- **会话 D 指纹**（实测提取）：
  ```
  Q    = 7cAxqu5OvS7cl7K6DL0Key3vtpbSwToW0ilvtKwmk/sPDSKtTZRkTWDLdvjMLNUB
  SALT = obfiowerehiring6bd5740ccccccccccccd0999999999999980999999999999980ccccccccccccd00
  ```
- **双向闭合验证**：

  | 方向 | 方法 | 结果 |
  |------|------|------|
  | 真值 → Q | 网络层抓到的 94 字符 `jmNOvyRgwDOgUhk8…` 解码反推内嵌 Q | == 当前 meta Q（`qMatch=true`） |
  | hook → SALT | 主世界注入 `<script>` hook `crypto.subtle.digest` 读明文输入 | `obfiowerehiring6bd574…` |
  | SALT + Q → 真值 | `gen_x_statsig_id(GET, /rest/app-chat/conversations, tf=98271610, r=142)` | **EXACT MATCH** 那条 94 字符 header |

- **抓取手法关键点**（解决 isolated world 隔离）：JSReverser 的 `evaluate_script` 跑在 isolated world，碰不到主世界 `crypto.subtle`；改用 isolated world 往 DOM 注入 `<script>`（在**主世界**执行）安装 hook，再用**真实 UI 点击**会话链接触发 grok 内部 client 发签名请求（手动 `window.fetch` 不走签名中间件，无效）。
- **SALT 结构印证「固定 m + Q 驱动旋转」**：后缀 `6bd574` = color `rgb(107,213,116)`（取自固定 m 矩阵的某行，可硬编码）；transform matrix 数字 ≈ `[0.8, 0.6, -0.6, 0.8, …]`（`0.8/0.6 ≈ cos/sin(37°)` 的旋转矩阵，角度由 `C`←Q 决定）。→ **同一 build 的固定 m，不同 Q 算出不同 SALT**。
- **22 条 digest 调用**跨 `conversations_v2`/`subscriptions`/`skills` 等端点，SALT **完全一致** → 第三次坐实「SALT 只依赖 Q」。
- 已固化进 [`x_statsig_id.py`](./x_statsig_id.py) 的 `_SELF_TEST_D`（运行见 `[session D ] PASS`）。

---

## 3. 完整调用链路

```
fetch(url, init)
  └─ ss(e)  [中间件，拦截所有 fetch]
       ├─ i = (0,l.v4)()                      // uuid → x-xai-request-id
       ├─ t = await sl(pathname, method)       // 生成 x-statsig-id
       │        └─ sl(n,i):
       │             t = t || new Promise(t => e.A(4629918).then(e => t(e.default())))
       │             let a = await t            // a = 签名函数（懒加载 module 1645000）
       │             return await a(n, i)
       ├─ catch(e): t = btoa("x0:" + e)         // 失败 fallback（本项目模仿的就是这个）
       └─ headers.set("x-xai-request-id", i)
          headers.set("x-statsig-id", t)
```

### 涉及的 JS 文件（cdn.grok.com/_next/static/chunks/）

| 文件名 | 作用 |
|--------|------|
| `0eiu~rv2bvc0~.js` | header 设置 + `ss` 中间件 + `sl` 懒加载封装 |
| `09.hvld5iazyb.js` | chunk `4629918` 加载器（→ `0u3n0ftyjlugz.js`，返回 module `1645e3`） |
| `0u3n0ftyjlugz.js` | **签名实现**（module `1645000`，obfuscator.io 混淆，sourcemap `0z_5cwkdieud`） |

---

## 4. 签名函数源码与闭包变量全解

### 4.1 签名函数 `a`（obfuscator.io 混淆，1085 字符）

```javascript
async (n, t) => {                       // n = pathname, t = method
  ...
  let m = Math.floor((Date.now() - p*1000) / 1000),   // p="1682924400" → timeFactor
      l = new Uint8Array(new Uint32Array([m]).buffer), // 时间因子 4B 小端
      Q = F,                                           // 设备指纹 48B（见 §5）
      S = z(Q);                                        // SALT 字符串（见 §5）
  return x(                                            // x = Uint8Array→base64(去=)
      new Uint8Array(
        [ Math.floor(Math.random()*256) ]              // 随机头 r
        .concat(
            Array.from(Q),                             // 48B
            Array.from(l),                             // 4B 时间
            (Array.from(await crypto.subtle.digest(    // SHA-256
                "sha-256",
                TextEncoder.encode([t,n,m].join("!") + S)
            ))).slice(0,16),                           // 取前 16B
            [3]                                        // 尾 L=3
        )
      ).map((n,idx,arr)=> idx ? n^arr[0] : n)          // XOR 随机头
  )
}
```

### 4.2 闭包变量解码表（断点 dump 自 `evaluate_on_callframe`）

| 变量 | 真实含义 | 说明 |
|------|----------|------|
| `W(t,r)` | 字符串解码器 | 自定义 base64 字母表 + RC4(`W.dJryxv`)，仅用于解出方法名 |
| `a` (外层) | `Date` | `a.now()` = `Date.now()` |
| `p` | `"1682924400"` | 基准秒（字符串），`p*1000` = 基准毫秒 |
| `l`(外层) | `Math` | |
| `s` | `Math.floor` | |
| `g` | `Math.random` | → 随机头 `r` |
| `R` | `Array.from` | Uint8Array→普通数组（便于 concat/map） |
| `b` | `n=>n.slice(0,16)` | 取 SHA-256 前 16 字节 |
| `x` | `n=>btoa(Array.from(n).map(c=>String.fromCharCode(c)).join("")).replace(/=/g,"")` | 字节→base64 去填充 |
| `y` | `crypto.subtle` 上的 digest 调用包装（`(n)=>subtle.digest("sha-256", K(n))`） | |
| `C` | `Uint32Array` | |
| `f` | `Uint8Array` | |
| `L` | `3` | 尾字节常量 |
| `V` | `(n,idx,arr)=> idx ? n^arr[0] : n` | XOR 随机头的 map 回调 |
| `F` | 48 字节数组 | **设备指纹 Q 的实际值**（见 §5） |
| `z` | 复杂函数 | 由 Q 派生 SALT 字符串并缓存到闭包变量 `A`（见 §5） |
| `O` | `()=>new Uint8Array(atob(...))` | Q 的备用来源（`Q = F || O()`，本会话走 F） |
| `j` | `"=,\r"` | 噪音（`Array.concat(j)` 后被 `slice(0,16)` 截断，无实际作用） |
| `c[...]` | 调用/运算包装器集合 | obfuscator.io 生成（如 `c.x(fn,a)=>fn(a)`、减法、取模等） |

---

## 5. 设备指纹 Q 与 SALT 来源

### 5.1 Q（48 字节）= SSR meta 标签 ✅ 已定位

**`Q = atob( document.querySelector('meta[name="grok-site―verification"]').content )`**

- ⚠️ meta 的 name 是 `grok-site―verification` —— 中间是 **U+2015 全角横线 `―`**，不是普通 `-`（刻意防 grep / 选择器命中）。
- content = 48 字节的标准 base64（64 字符）。
- **存在于服务端 SSR 原始 HTML 中**（`fetch('/')` 可见，`ssrHasMeta=true`）→ **Python `requests.get` 即可抓取，无需浏览器跑 JS**。
- **每个 HTML 文档下发不同的 Q**（连续两次 `GET /`：`BqebdYTA…` ≠ `o/Iv77ro…`）。即每次页面加载绑定一个新指纹种子。
- 签名函数中 `Q = F || O()`，`O()` 即读取此 meta（`元素.textContent` → `atob` → 字节）；`F` 为会话内缓存。

### 5.2 SALT = `z(Q)`，**已实验证实为确定性纯函数**

> **实验（预言机法）**：用 preload 在文档解析期持续把 meta 的 content 强制覆盖为会话 B 的 `Q_B`（`BqebdYTA…`），reload 进入**全新会话**（timeFactor `98185915→98187296`，相差 1381s）。结果前端算出的 SALT 仍为 `obfiowerehiring4b58cf100100`，与会话 B **完全一致**。
> → **相同 Q ⇒ 相同 SALT**，与时间 / 随机 / 会话无关，SALT 完全由 Q 决定。故服务端用其下发的 Q 重算 `f(Q)` 即可校验；**纯生成式（方案 B）成立，随机 SALT（方案 C）不可行**。
> 附带价值：此 preload「固定 Q → 读 SALT」构成一个**标定预言机**，可喂入特制 Q 黑盒推导 `z` 的字节→hex 映射。

- SALT 前缀 `obfiowerehiring` 是签名函数 `a` 里拼接的字面常量（"obf io we're hiring" 招聘彩蛋）；`z(Q)` 只产出其后的 hex 后缀（会话 B：`4b58cf100100`）。

**z(Q) 机制（断点 dump 完全揭示）—— 浏览器 CSS / Web-Animations 渲染指纹：**

| 步骤 | 源码（去混淆） | 说明 |
|------|----------------|------|
| ① 颜色表 | `m = h(".r-7ya3u", Q)` | 从页面 CSS 选择器 `.r-7ya3u` 提取的 **16×11 数字矩阵**（CSS 指纹） |
| ② 索引 | `a = Q[22] % 16`；`C = f(Q[14],Q[36],Q[33])` | a 选颜色组；C → 动画 currentTime |
| ③ 建元素 | `[l,H] = I()` → `createElement` + `body.append` | 临时 DOM 元素 |
| ④ 动画 | `Z(l, m[a], C)` → `l.animate(...)`；`anim.currentTime = g(C)` | 用 m[a] 派生关键帧驱动动画到 C 时刻 |
| ⑤ 读回 | `x = getComputedStyle(l)`（`P` = `getComputedStyle` native） | 读插值后的样式 |
| ⑥ 拼装 | `("" + x.color + x.transform).match(/([\d.-]+)/g).map(→hex).join("")` | 提取 color+transform 全部数字转 hex |

**实例（会话 B，`Q[22]=52 → a=4`）**：`m[4][:3]=[75,88,207]` → `color "rgb(75,88,207)"` → `4b58cf`；`transform=matrix(1,0,0,1,0,0)` → 数字 `1,0,0,1,0,0` → `100100`。拼成 **`4b58cf100100`** ✅。
（`new S(()=>{…})` 那段 `OfflineAudioContext`/`Math.random` 音频指纹赋值给闭包 `j`，用于**其他**字段，**不参与** SALT。）

- **确定性**：`det=true`（重置缓存 `A` 后 `z(Q)` 重算仍得同值）。color/transform 是 `currentTime` 时刻的**插值**结果——会话 A 的浮点尾数 `…999…a` 即落在动画中间的插值。
- **关键推断（服务端校验）**：服务端要校验 `SHA256("{M}!{path}!{tf}"+SALT)`，只掌握自己 SSR 下发的 Q → SALT 必为 `f(Q)`，与本实验 `det=true` 一致。

### 5.2.1 字节依赖：静态解混淆确认（2026-06-11）—— 决定查找表规模

把签名 chunk（`0u3n0ftyjlugz.js`，module `1645e3`）从 CDN 直接拉下来，在 Node 里离线调出其 obfuscator.io 字符串解码器 `W(idx,key)`（base64+RC4），把签名函数体里所有 `W(...)` 调用还原成明文，得到 z(Q) 的可读源码。**结论：z(Q) 只读 Q 的 4 个字节，且每个先 `%16`：**

```js
let [a, C] = [
   Q[22] % 16,                                  // a：选颜色组（m[a]）
   (Q[14] % 16 + Q[36] % 16) - Q[33] % 16       // C：合成动画 currentTime
];
m = h(".r-7ya3u", Q);   // 颜色矩阵 = build-time CSS 常量（与 Q 无关）
```

- 全函数体对 `Q[i]` 的下标访问经作用域核对仅 `Q[22]/Q[14]/Q[36]/Q[33]` 属于 z(Q)；`Q[0..6]` 那批是 `T=n=>({color:[…M(n[0])…]})` 里**颜色矩阵某一行**的局部参数，不是 Q。
- **可枚举性**：`a ∈ [0,16)`（16 种），`C ∈ [−15,30]`（≤46 种）→ `(a,C)` 组合 **≤ 16×46 = 736**。SALT 完全由 `(a,C)` 决定（color 来自 `m[a]` 插值，transform 角度也来自 `m[a]` 行）。
- **意义**：全世界所有可能的 SALT **最多 ~736 种** → 理论上**档次 B（标定→查找表）可行**：枚举 ≤736 种 `(a,C)`→SALT 建表。

#### 5.2.1.1 ⚠️ 决定性发现（2026-06-11 活体断点复测）：查找表"按 build 绑定"，档次 B 不值得做

你手动过 CF 后，在 z(Q) 正常工作的真实浏览器里，通过 `crypto.subtle.digest` 调用栈定位到**当前 build** 的签名 chunk（`0vu5gegy_t7j9.js`，仍 module `1645e3`），在 digest 调用处下文本断点命中，dump 出 SALT 计算函数 `j`（即 z）的去混淆源码并**对当前 Q 重算出完全一致的 SALT**（预言机成立）。但同时暴露两个让档次 B 失去价值的事实：

**① z(Q) 依赖的 4 个字节索引随 grok 发版漂移**——结构不变（仍 4 字节、各 `%16`、≤736 组合），但**具体哪 4 个字节每次发版都会变**：

| | 旧 build（会话 B/C，`0u3n0ftyjlugz.js`） | 当前 build（`0vu5gegy_t7j9.js`） |
|---|---|---|
| 选色组 `a` | `Q[22] % 16` | **`Q[45] % 16`** |
| 动画时刻 `C` | `(Q[14]+Q[36]−Q[33]) % 16` | **`(Q[9]+Q[36]−Q[30]) % 16`** |
| 颜色矩阵选择 | （随 build） | 另含 `Q[5] % 4` 选矩阵分支 |

**② color 与 transform 都是 Web-Animations 在 `currentTime` 时刻的活体插值**——断点暂停时 JS 冻结、动画时钟停摆，此时调 `j(Q)` 只能拿到动画**起始帧**：实测冻结态枚举 736 项，`distinct` 仅 16、transform 全平凡 `100100`、且 color 也错（O=5,S=5 算出 `386923…` ≠ 真实 `37682a…`）。**必须在正常运转（未暂停）的页面里调 `j` 才能得到正确 SALT。**

**结论**：①+② 叠加 ⇒ 查找表是**「按 build 版本绑定」**的——grok 每次发版，4 个字节索引漂移、颜色矩阵变、整张表作废，都得重新逆向 chunk + 重新活体标定。这与档次 B「纯 Python 永不用浏览器」的初衷相悖，会变成持续维护负担。**反观档次 A（每会话 hook `crypto.subtle.digest` 读 SALT）天然抗 build 变化**——它读的是当前代码实际算出的值，不关心字节索引怎么漂。故**生产落地用档次 A；档次 B 原理已验证，但不值得做。**

#### 5.2.2 z(Q) 拼装层完全破解（2026-06-11）：「活体插值玄学」被推翻

> 此前（§5.2 / §5.2.1.1）把 z(Q) 的 color/transform 当作"无法纯算的浏览器渲染玄学"。把签名 chunk 去混淆到**原语级**后，最唬人的那串 `…28f5c28f5c28f6…` 真相大白——**它不是玄学，是 JS `Number.prototype.toString(16)` 的浮点输出**。

**z(Q) 完整去混淆源码（变量名还原）**：

```js
// h(sel, Q): 从 .r-7ya3u 容器里第 (Q[5]%4) 个 SVG <path d> 提取颜色/几何矩阵 m
h = (sel, Q) => J( G(k(sel))[Q[5]%4].childNodes[0].childNodes[1], "d" )  // 取 path 的 d 属性
        .substring(9).split("C")                                          // 按 SVG 三次贝塞尔 C 命令分段
        .map(seg => seg.replace(/[^\d]+/g," ").trim().split(" ").map(Number));  // 每段数字 -> 行

z = (Q) => {
  let [a, C] = [ Q[22]%16, (Q[14]%16 + Q[36]%16) - Q[33]%16 ];  // (旧 build 索引)
  let m = h(".r-7ya3u", Q);                  // 颜色/几何矩阵（build 常量，与 Q 无关）
  let [el, cleanup] = createTempElement();
  el.animate( T(m[a]), C派生的keyframes );   // T(row) 由 m[a] 行生成 color/rotate 关键帧
  anim.currentTime = g(C);                   // 推进到 C 时刻
  let cs = getComputedStyle(el);
  A = Array.from( ("" + cs.color + cs.transform).match(/([\d.-]+)/g) )   // 提取所有数字
        .map(n => parseFloat(parseFloat(n).toFixed(2)).toString(16))     // ★ 关键拼装
        .join("").replace(/[.-]/g, "");      // 去掉所有 '.' 和 '-'
  cleanup();
  return A;
};
```

**关键拼装层（`salt_assembly.py` 已逐字符复刻，全 PASS）**：每个数字 → `toFixed(2)` 截断 2 位小数 → `Number.toString(16)`（**浮点 16 进制**）→ 拼接 → 删除所有 `.` 和 `-`。

| 输入 | `(n).toString(16)` | 去符号后 |
|---|---|---|
| `0.16` | `0.28f5c28f5c28f6` | `028f5c28f5c28f6` |
| `0.5` | `0.8` | `08` |
| `1` | `1` | `1` |

**端到端验证**（纯 Python，无反推）：

| 会话 | color(整数 RGB 行→hex) | transform matrix 数字序列 | 拼出后缀 | vs 真值 |
|---|---|---|---|---|
| B | `[75,88,207]`→`4b58cf` | `1,0,0,1,0,0` | `4b58cf100100` | ✅ EXACT |
| C | `[34,70,191]`→`2246bf` | `1,0,0.16,0,0.16,1,0,0` | `2246bf10028f5c28f5c28f60028f5c28f5c28f6100` | ✅ EXACT |

**这改写了 z(Q) 各步的纯算可行性判定**：

| 步骤 | 内容 | 纯算可行性（修订后） |
|---|---|---|
| ① 字节选择 | `a=Q[i]%16`、`C=f(Q[j..])` | ✅ 纯算（但索引按 build 漂移，见 §5.2.1.1） |
| ② **m 矩阵** | `.r-7ya3u` 的 SVG `<path d>` 解析 | ⚠️ **唯一非纯算输入**：build 常量，但**不在 SSR HTML、不在签名 chunk**（实测 SSR 有 meta(Q) 但 `svg/path=0`），是运行时 React 挂载的图标 → 须浏览器渲染提取一次/每 build |
| ③ color | 取 `m[a]` 整数 RGB 行（实测 B/C 均为整数 rgb，**未真插值**） | ✅ 纯算（已有 m 时） |
| ④ transform | 动画在 `currentTime=g(C)` 的 matrix 插值（cubic-bezier） | ✅✅ **已纯 Python 正向闭合（§5.2.3，`salt_assembly.py`）**：cubic-bezier easing + rotate→matrix 与 Chrome Web-Animations computed matrix 逐位吻合到 6 位小数 |
| ⑤ **拼装** | `toFixed(2)`→`toString(16)`→去符号 | ✅✅ **本节已逐字符复刻（`salt_assembly.py`）** |

**修订结论**：旧判断"必须靠浏览器活体插值、纯算根本不可能"**被彻底推翻**。SALT 的**算法**不再是黑盒——①③④⑤ 全部纯算实证（④ 的 cubic-bezier 插值见 §5.2.3，与 Chrome 引擎逐位吻合）。**唯一真正非纯算的输入只剩 m 矩阵（运行时 SVG 图标 path）**，它是 build 常量。故纯算路线（B′）从"每会话开浏览器"降级为"每 build 提取一次 m + 标定字节索引"。但 ②m + ①索引仍按 build 漂移，维护成本依旧高于档次 A。**生产仍推荐档次 A**，但"纯算不可能"的旧定性已纠正为"纯算可行、只是 m 须每 build 取一次"。

#### 5.2.3 ④ transform 插值正向闭合（2026-06-12）：cubic-bezier 与 Chrome 引擎逐位一致

> §5.2.2 已纯算复刻 ⑤ 拼装层，但 ④（transform 的 cubic-bezier matrix 插值）当时仍记为"确定数学但尚未独立实证"。本节把 ④ 也正向闭合：纯 Python 复刻 W3C cubic-bezier 求值 + 旋转 matrix 插值，输出与 Chrome Web-Animations 的 computed matrix **逐位吻合到 6 位小数**。

**先把 z 的动画构造从去混淆源 `_chunks/body_cur.js` 还原（变量名复原）**：

```js
A(row) = {                                            // row = m[a]，11 个 0-255 整数
  color:    ["#"+RGB(row[0..2]), "#"+RGB(row[3..5])],
  transform:["rotate(0deg)", "rotate("+H(row[6],60,360,true)+"deg)"],
  easing:   "cubic-bezier("+row.slice(7).map((v,i)=>H(v, i%2?-1:0, 1))+")"
}
H = (n,t,r,c) => { u = n*(r-t)/255 + t; return c ? floor(u) : +u.toFixed(2) }
// E: W = el.animate(A(row), dur=4096); W.pause(); W.currentTime = round(C/10)*10
//    cs = getComputedStyle(el); 提取 cs.color + cs.transform 的所有数字
```

**关键解出 `currentTime` 公式**（此前一直卡在这里）。去混淆后 E 里那行的算子是三层嵌套 `o[...]` 引用，逐个查 build 的算子表：

| 算子 key | 定义 |
|---|---|
| `hGLGR`（外层） | `n*W` 乘法 |
| `vWSpQ`（中层） | **`n(W)` 函数调用**（一度被误当成乘法 → 公式解错，是之前卡壳的根因） |
| `dFXaJ`（内层） | `n/W` 除法 |

故 `currentTime = hGLGR( vWSpQ(M, dFXaJ(C,10)), 10 ) = M(C/10)*10 = round(C/10)*10`（`M=Math.round`）。即 ct 量化到 10ms 网格，C∈[−15,30] → ct∈{0,10,20,30}（小角度，动画刚起步）。

**纯算 vs Chrome 引擎逐位比对**（同一 easing `cubic-bezier(0.71,-0.43,0.89,0.47)`，rotate→matrix）：

| ct (ms) | 值进度 p（含负 overshoot） | Chrome computed matrix | 纯 Python forward |
|---|---|---|---|
| 0 | 0 | `1, 0, 0, 1` | `1, 0, 0, 1` ✅ |
| 10 | −0.001475 | `0.999991, -0.00422082` | `0.999991, -0.004221` ✅ |
| 100 | −0.014384 | `0.999153, -0.041159` | `0.999153, -0.041159` ✅ |
| 320 | −0.043082 | `0.992406, -0.123004` | `0.992406, -0.123004` ✅ |
| 1000 | −0.102613 | `0.957176, -0.289508` | `0.957176, -0.289508` ✅ |

> 控制点 y 为负（−0.43）→ bezier 在 t 小处先反向 overshoot，p<0，这正是会话 A 浮点尾数落在动画"反向中间态"的来源。

**端到端纯算闭合**（`salt_assembly.py` 的 `build_z_suffix(row, C)`，无任何反推）：

| 向量 | row = m[a] | C → ct | 拼出后缀 | vs 真值 |
|---|---|---|---|---|
| run1 平凡 | `[221,181,84,119,84,7,…]` | 1 → 0 | `ddb554100100` | ✅ EXACT |
| run1 非平凡 | 同上 | 15 → 20 | `ddb55410028f5c28f5c28f60028f5c28f5c28f6100` | ✅ EXACT |

后者的 sin 项 `0.0084` 经 `toFixed(2)`→`0.01`→`toString(16)`→`028f5c28f6`，真正经过了 cubic-bezier overshoot 数学，非平凡闭合。

**修订**：§5.2.2 表中 ④ 由"尚未独立实证"升级为 **✅✅ 纯算逐位闭合**。至此 z(Q) 全链 ①③④⑤ 均纯 Python 实证，唯一非纯算输入只剩 ② m 矩阵（运行时 SVG，每 build 取一次）。

> ⚠️ 精度注记：Python `round` 是 round-half-to-even，JS `Math.round` 是 round-half-up，二者对 `.5` 边界不同（如 C=5 → JS ct=10 而 Python round 给 0）。`salt_assembly.py` 用 `js_round`（`floor(x+0.5)`）对齐 JS 语义，避免 ct 量化与 color 通道 round 的边界偏差。

### 5.3 离线复刻路线（落地 grok2api）

| 方案 | Q 来源 | SALT 来源 | 适用 |
|------|--------|-----------|------|
| **A 提取式（已实测可用，推荐）** | 浏览器/HTTP 抓 meta | 浏览器 hook 一次 `crypto.subtle.digest` 读明文输入取 SALT | ✅ 立即可用、**天然抗 build 变化**；每账号/会话提取一组 (Q,SALT)。本文 §2.4 即用此法实测 8/8 复刻 |
| **B 标定→查找表（原理已验证，但不推荐）** | Python `GET /` 抓 meta | 预言机标定 ≤736 种 `(a,C)`→SALT 建表 | ⚠️ 原理通（§5.2.1）但**按 build 绑定**（§5.2.1.1）：4 字节索引随发版漂移 + color/transform 须活体插值，grok 每发版整表作废需重新逆向+标定，维护成本高 |
| **B′ 纯算复刻 z(Q)** | Python 抓 meta | 纯 Python：m 每 build 提取一次 + 复刻插值/拼装 | ⚠️ **已全链纯算实证（§5.2.2 + §5.2.3）**：拼装⑤ 逐字符复刻、color③ 纯算、插值④ 与 Chrome 引擎逐位一致；唯一非纯算输入是 m 矩阵（运行时 SVG path），须每 build 取一次。仍不如 A 省事（①索引+②m 均按 build 漂移） |
| **C 试探** | 任意自洽 48B | `obfiowerehiring`+随机 | ❌ 基本不可行：服务端用其下发的 Q 重算 `f(Q)` 校验，随机 SALT 会失配 |

> **落地建议**：
> - **推荐 = 方案 A（且为终态）**：headless Chromium / CDP 打开 grok.com，读 meta 得 Q + hook `crypto.subtle.digest` 输入解析 SALT（输入格式 `"{M}!{path}!{tf}{SALT}"`，去掉前三段即 SALT），缓存 (Q, SALT)；之后用 `x_statsig_id.py` 的 `ExtractedFingerprint` 纯 Python 高频签名，直到指纹轮换再刷新。**本文 §2.4 的 8/8 EXACT 即用此法验证。** 关键优势：读的是当前代码实际算出的 SALT，**grok 发版改字节索引也不受影响**。
> - **方案 B 已被实测否决**：查找表按 build 绑定（§5.2.1.1），相比 A 多了"每次发版重新逆向+标定"的维护负担，却只省掉"每会话一次浏览器 hook"，得不偿失。原理验证留档即可，不落地。

### 5.4 ⚠️ 运行时实测：官方前端自身降级为 x0，服务端接受（2026-06-11）

在「CDP 远程调试 + 代理 7897 + Chrome 149 + grok 新构建（sentry-release `4dc4856…`）」环境下复测，发现一个改变落地结论的事实：

- **官方前端的 `z(Q)` 自己就抛异常**：`TypeError: Cannot read properties of undefined (reading 'childNodes')`（z 的 DOM/CSS 指纹读取在本环境失败，未走到 `crypto.subtle.digest`）。
- fetch 中间件 `ss` 的 catch 分支随即发送 **`btoa("x0:" + 该错误)`**：
  ```
  x-statsig-id: eDA6VHlwZUVycm9yOiBDYW5ub3QgcmVhZCBwcm9wZXJ0aWVzIG9mIHVuZGVmaW5lZCAocmVhZGluZyAnY2hpbGROb2Rlcycp
  解码 = "x0:TypeError: Cannot read properties of undefined (reading 'childNodes')"
  ```
- **服务端照常返回 200**：`/rest/modes`、`/rest/suggestions/profile`、`/rest/app-chat/conversations`、`/rest/workspaces`、`/rest/skills` 全部成功返回真实数据。两次独立加载（含一个**无任何注入的全新标签页**）结果一致 → 排除调试干扰。

**推断**：x-statsig-id 现阶段更像「尽力而为的遥测/风控信号」，而非硬闸门；真正反爬校验由 `cf_clearance` + `x-challenge` + `x-signature` + `sso` 承担。z(Q) 在 CDP/自动化环境下抛错，也提示它可能带**反自动化探测**——这意味着「CDP 提取 SALT」并不稳定，方案 A 需用尽量贴近真实用户的浏览器环境。

> ⚠️ 边界：以上为 read/init 端点的观测；**聊天补全端点（发消息）是否同样宽松尚未实测**（涉及账号配额与风控，未擅自触发）。

#### 5.4.1 状态演进：当前 build 下 z(Q) 又**正常工作**了（2026-06-12，会话 D）

同一套 CDP + 代理 + Chrome 149 环境，但 grok 已更新到 **sentry-release `9d769be3…`**（≠ §5.4 的 `4dc4856…`）。本次实测结论与 §5.4 **相反**：

- **官方前端 `z(Q)` 正常工作**：页面自发的 `/rest/app-chat/conversations` 请求带的是**真签名**（94 字符、非 x0 兜底）——`jmNOvyRgwDOgUhk8…J5ZXFjQ`，反推内嵌 Q == 当前 meta Q。
- 主世界 hook `crypto.subtle.digest` 抓到 **22 条**明文输入，当前 build 真实 SALT = `obfiowerehiring6bd5740ccccccccccccd0999999999999980999999999999980ccccccccccccd00`。
- 用此 (Q, SALT) 纯 Python `gen_x_statsig_id` 重算页面那条真签名 → **EXACT MATCH**（详见 §2.5、`_SELF_TEST_D`）。

**解读**：z(Q) 是否抛错**取决于具体 build + 页面 UI 状态**（`.r-7ya3u` 元素当时是否挂载），不是稳定特征——§5.4 那次是恰好读不到元素、§5.4.1 这次读到了。这对落地的含义：

- x-statsig-id 仍非硬闸门（x0 兜底照样 200），**§6 的「保守对齐 x0」结论不变**。
- 但「方案 A 提取 SALT」的可行性得到正面印证：**在 z(Q) 正常的 build 上，hook 一次即可拿到真实 SALT 并纯算复刻**——本节即为实证。

> ⚠️ 提取注意：JSReverser 的 `evaluate_script` 跑在 **isolated world**，碰不到主世界 `crypto.subtle`；须用 `inject_preload_script` 失败时改为**从 isolated world 往 DOM 插 `<script>`**（在主世界执行）来 hook，且触发签名须用 **grok 自己的内部 client**（真实 UI 点击 / 路由跳转），手动 `window.fetch` 不走签名中间件。

---

## 6. 对本项目的意义与集成建议

`app/dataplane/proxy/adapters/headers.py` 的 `_statsig_id()` 目前返回 `btoa(前缀+error)` 形态的**降级失败值**（模仿前端 catch fallback）。**§5.4 实测表明这与官方前端自身的失败路径同形、且被服务端接受**，故现状可用；唯一不精确处是前缀用了 `e:`/`x1:`，而官方当前观测为 `x0:`（错误体一致）。

**两条可选改进（按需）：**

**① 保守对齐（推荐，零浏览器依赖）**：把默认兜底逐字节对齐官方观测的 `x0:` 值——用 [`x_statsig_id.py`](./x_statsig_id.py) 的 `official_fallback_value()`。改动最小、风险最低。

**② 升级为真签名（需浏览器低频取指纹）**：用 §1 真实算法 + 提取式指纹替换。关键依赖是每个 grok 会话的 `Q`+`SALT`：
- **取指纹（低频）**：headless Chromium / CDP 打开 grok.com → 读 meta 得 `Q`、hook `crypto.subtle.digest` 输入解析得 `SALT`（或按 §2.2 反推）；随账号/会话缓存。
- **签名（高频）**：用 [`x_statsig_id.py`](./x_statsig_id.py) 的 `ExtractedFingerprint(q_b64, salt).sign(method, path)` 纯 Python 生成——带正确时间戳、每次随机头的真实签名，无需每次起浏览器。
- **轮换**：指纹失效（服务端换 Q / 会话过期）时重新取一次即可。
- 纯算生成 `SALT` 不可行（见 §5.2：浏览器渲染指纹）；故无法完全去浏览器，但浏览器仅用于低频取指纹。

---

## 7. 复现环境与操作备忘

```bash
# 启动带远程调试 + 代理的 Chrome
"/c/Program Files/Google/Chrome/Application/chrome.exe" \
  --remote-debugging-port=9222 \
  --proxy-server=127.0.0.1:7897 \
  --user-data-dir="/c/Users/yuandeace/.chrome-jsreverse" \
  --no-first-run --no-default-browser-check \
  "https://grok.com"

curl -s http://127.0.0.1:9222/json/version   # Chrome 148.0.7778.216
```

关键技巧（经验总结）：
- **优先 preload hook 而非断点**：`inject_preload_script` 注入 `crypto.subtle.digest`/`Headers.set` 拦截器，reload 后由页面自身初始化请求触发签名，**不冻结页面**，可批量捕获哈希输入/输出。远比断点稳健（断点列号会因重新部署失效、且冻结页面有 Cloudflare 超时风险）。
- **最终 header 直接读网络请求**：`get_network_request` 的 request headers 即含真实 `x-statsig-id`，配合捕获的 digest 可离线验证布局。
- 登录态：把 grok session JWT 写入 `sso` / `sso-rw` cookie 后 reload 即可（凭证敏感，勿入库）。
- 未登录或限流（"需求量高"）时，发送消息不会触发签名请求；但 reload 的初始化批请求（rate-limits/modes/conversations…）始终签名。
```
