# grok.com `x-statsig-id`：项目原本算法 vs 还原的真实算法 — 完整对比

> 目标：把本项目里**原本**的 `x-statsig-id` 生成逻辑（`_statsig_id()`），与逆向**还原的真实算法**（`gen_x_statsig_id()`）做逐项对比。
> 关联文档：[`x-statsig-id-逆向分析.md`](./x-statsig-id-逆向分析.md)（真实算法的完整还原过程）、参考实现 [`x_statsig_id.py`](./x_statsig_id.py)。
> 文中"实算样本"均为本机真实运行 `x_statsig_id.py` 产出，可复现。
> 最后更新：2026-06-11

---

## 0. TL;DR（本质区别）

> **项目原本的 `_statsig_id()` 根本不是"签名"——它只是把一段假的 JS 报错字符串 base64 一下，模仿前端「出错兜底」那条分支。还原的 `gen_x_statsig_id()` 才是前端「正常成功」那条分支的真·SHA-256 签名算法。**
>
> 两者模仿的是**同一个前端函数（fetch 中间件 `ss`）的两条相反路径**：

```
try:      t = await sl(pathname, method)   ← 真签名     →  gen_x_statsig_id() 还原的就是这里
catch(e): t = btoa("x0:" + e)              ← 出错兜底   →  _statsig_id() 模仿的就是这里
headers.set("x-statsig-id", t)
```

| | 【A】项目原本 `_statsig_id()` | 【B】还原真实算法 `gen_x_statsig_id()` |
|---|---|---|
| 本质 | base64(一句**假报错文本**) | 真·**SHA-256** 密码学签名 |
| 模仿前端分支 | `catch` 失败兜底 | `try` 成功签名 |
| 解码后 | **可读英文报错** | **70 字节二进制**（不可读） |
| 今天能否通过服务端 | ✅ 能（x-statsig-id 当前非硬闸门） | ✅ 能 |
| 若上游开启硬校验 | ❌ 全废 | ✅ 仍过（前提 (Q,SALT) 有效） |

---

## 1. 源码对照

### 【A】项目原本 — `app/dataplane/proxy/adapters/headers.py` 的 `_statsig_id()`

> ⚠️ 2026-06-11 已实装「保守对齐」改进①：前缀从旧的 `e:`/`x1:` **统一改为官方当前实际发送的 `x0:`**。下面是当前真实代码。

```python
def _statsig_id() -> str:
    cfg = get_config()
    if cfg.get_bool("features.dynamic_statsig", False):
        # 动态模式：每次生成内容不同的 x0 兜底
        if random.choice((True, False)):                          # 50/50 抛硬币
            rand = "".join(random.choices(ascii_lowercase + digits, k=5))
            msg = f"x0:TypeError: Cannot read properties of null (reading 'children['{rand}']')"
        else:
            rand = "".join(random.choices(ascii_lowercase, k=10))
            msg = f"x0:TypeError: Cannot read properties of undefined (reading '{rand}')"
        return base64.b64encode(msg.encode()).decode()            # ← 仅仅是 base64(报错文本)
    # 静态默认 (dynamic_statsig=false)：逐字节对齐官方 x0 兜底值
    return ("eDA6VHlwZUVycm9yOiBDYW5ub3QgcmVhZCBwcm9wZXJ0aWVzIG9mIHVuZGVmaW5lZCAo"
            "cmVhZGluZyAnY2hpbGROb2Rlcycp")                        # = base64("x0:TypeError...childNodes")
```

- 无 SHA-256、无 Q、无 SALT、无 timeFactor、无异或；与请求的 method/路径**完全无关**。
- 两种模式：`dynamic_statsig=true` → 每次随机假报错（前缀 `x0:`，变量名随机）；`false` → 固定静态值（前缀 `x0:`，逐字节对齐官方）。

### 【B】还原真实算法 — `docs/reverse/x_statsig_id.py` 的 `gen_x_statsig_id()`

```python
def gen_x_statsig_id(method, pathname, Q, salt, ts=None, r=None):
    tf      = int(ts or now) - 1682924400                          # timeFactor（基准 2023-05-01）
    msg     = f"{method.upper()}!{pathname}!{tf}{salt}".encode()   # 绑定 方法+路径+时间+盐
    digest  = hashlib.sha256(msg).digest()                         # ← 真 SHA-256（非 HMAC）
    r       = r if r is not None else random.randrange(256)        # 随机头 1 字节
    payload = bytes([r]) + Q + struct.pack("<I", tf) + digest[:16] + bytes([3])   # 70 字节
    out     = bytes([payload[0]] + [b ^ r for b in payload[1:]])   # 除头外整体异或 r（混淆）
    return base64.b64encode(out).decode().rstrip("=")              # 94 字符（去 =）
```

- 字节布局（异或前的 payload，共 70B）：`[r(1)] + Q(48) + uint32LE(tf)(4) + SHA256[:16](16) + [L=3](1)`。
- 已逐字符复刻浏览器真值（见逆向文档 §2.3 EXACT MATCH）。
- 前提：需要该会话的 `Q`(48B 设备指纹) 与 `SALT`（= `obfiowerehiring` + `z(Q)` 浏览器渲染指纹）。

---

## 2. 实算样本对照（本机真实运行产出）

| 来源 | 实际值（截断） | base64 解码后 |
|---|---|---|
| **A 静态** `x0:`（当前默认） | `eDA6VHlwZUVy...Jyk`（**92** 字符，逐字节对齐官方） | `x0:TypeError: Cannot read properties of undefined (reading 'childNodes')` ← **可读，与官方一致** |
| **A 动态** `x0:` ① | `eDA6VHlwZUVy...` | `x0:TypeError: ...null (reading 'children['pb4th']')` ← **可读，变量名随机** |
| **A 动态** `x0:` ② | `eDA6VHlwZUVy...` | `x0:TypeError: ...undefined (reading 'ihbutdfpmq')` |
| **B 真签名** ① | `eH7f4w38uIC5yiKoMLbjEF12cNxpcUhMMpc/30VlhCZsTgCm2jhIbzICW2QWZAi8...PThGbew` | 70 字节**二进制乱码**，`out[0]=120`（随机头） |
| **B 真签名** ② | `d3HQ7ALzt4+2xS2nP7nsH1J5f9NmfkdDPZgw0EpqiyljQQ+p1TdHYD0NVGsZawez...` | 70 字节二进制，`out[0]=119` |
| **B 真签名** ③ | `HBq7h2mY3OTdrkbMVNKHdDkSFLgNFSwoVvNbuyEB4EIIKmTCvlwsC1ZmPwByAGzY...` | 70 字节二进制，`out[0]=28` |

> **2026-06-11 已实装改进①**：项目兜底前缀已从旧的 `e:`（静态）/ `x1:`（动态）**统一对齐官方当前实际发送的 `x0:`**（静态默认值即 `official_fallback_value()` 的逐字节结果）。错误体与官方几乎一致，仅当年前缀对不上的问题已修复。

---

## 3. 逐维度对比

| 维度 | 【A】项目原本 `_statsig_id()` | 【B】还原真实 `gen_x_statsig_id()` |
|---|---|---|
| **本质** | base64(一句假报错文本) | 真·SHA-256 密码学签名 |
| **模仿前端哪条分支** | `catch(e){ btoa("x0:"+e) }` **失败兜底** | `await sl(path,method)` **成功签名** |
| 含 SHA-256 | ❌ | ✅ |
| 含设备指纹 Q(48B) | ❌ | ✅ |
| 含 SALT = z(Q) | ❌ | ✅（浏览器 CSS/Web-Animations 渲染指纹） |
| 含 timeFactor | ❌ | ✅ uint32LE，绑定当前时间 |
| 含随机头 XOR 混淆 | ❌ | ✅ `out[i]^=r` |
| 与 METHOD / 路径绑定 | ❌ 完全无关 | ✅ 进哈希输入 `"{M}!{path}!{tf}{salt}"` |
| 解码后形态 | **可读英文报错** | **70 字节二进制**（不可读） |
| 输出长度 | 96 字符（动态可变，**带 `=`**） | 固定 **94** 字符（**去 `=`**） |
| 前缀特征 | `x0:`（已对齐官方，静态/动态均是） | 无前缀（头是随机字节 `r`） |
| 运行时依赖 | 零依赖 | 需每会话 `(Q, SALT)`；SALT 必须真浏览器提取 |
| 随机性来源 | 假报错里的随机变量名 | 随机头 `r`（每次 0–255，每调用不同） |
| 可被服务端"重算校验" | ❌ 无意义 | ✅ 服务端用其下发的 Q 重算 `SHA256(...+f(Q))` |

---

## 4. 为什么差这么多：模仿前端同一函数的两条相反分支

前端 fetch 中间件 `ss` 拦截所有请求并设置 `x-statsig-id`：

```
fetch(url, init)
  └─ ss(e)
       ├─ try:   t = await sl(pathname, method)   // 懒加载真签名函数（botoxSign）
       │            → 内部 SHA-256 + Q + SALT + XOR  →  B 还原的就是这条
       ├─ catch(e): t = btoa("x0:" + e)            // 签名失败时的兜底  →  A 模仿的就是这条
       └─ headers.set("x-statsig-id", t)
```

- **A（项目原本）**：直接伪造 catch 分支的产物——一段假报错。它赌的是"服务端对这个头校验很松，发个看起来像前端失败兜底的值也能过"。
- **B（还原算法）**：实现 try 分支的真实签名逻辑，能产出与浏览器逐字符一致的 94 字符真签名。

---

## 5. 实战意义与风险画像（决定该用哪个）

**当前时间点（2026-06-11），两者服务端都返回 200。** 原因见逆向文档 §5.4：x-statsig-id **现阶段不是硬闸门**，真正的反爬闸口是 `cf_clearance` + `sso` +（部分端点）`x-challenge` / `x-signature`。所以项目原本那个"假报错"今天能用——不是因为它正确，而是因为服务端现在不校验它。

但两者的风险完全不同：

| | 【A】项目原本（假报错） | 【B】还原真实算法 |
|---|---|---|
| 今天能用？ | ✅ 能（服务端宽松） | ✅ 能 |
| 上游若开启硬校验 | ❌ **全废**（`x0:` 假报错被识破） | ✅ 仍过（前提：(Q,SALT) 有效未轮换） |
| 落地成本 | 零依赖，纯字符串 | 需真浏览器为每会话**低频提取一次** `(Q, SALT)`；`SALT=z(Q)` 算法可纯算，但唯一非纯算输入 m 矩阵须每 build 取一次（见 §5.2.2 订正 / 下方注） |
| 维护 | 几乎为零 | 指纹轮换/会话过期时需重取 |

**结论**：
- **A = 赌服务端不校验**：零成本、今天有效、随上游收紧可能集体失效。
- **B = 真签名**：抗未来收紧，代价是必须低频跑一次浏览器取指纹。

### 改进路线（与逆向文档 §6 一致）

- **① 保守对齐（✅ 已实装，零浏览器依赖）**：`_statsig_id()` 的兜底前缀已从旧的 `e:` / `x1:` 对齐成官方当前真实发送的 `x0:`（静态默认 + 动态模式均为 `x0:`，见 §1【A】）。逐字节对齐的静态值等价于 `x_statsig_id.py` 的 `official_fallback_value()`。改动最小、风险最低，**当前生产即此状态**。
- **② 升级真签名（需浏览器低频取指纹）**：用 `ExtractedFingerprint(q_b64, salt).sign(method, path)` 替换 `_statsig_id()`。
  - 取指纹（低频）：headless Chromium / CDP 打开 grok.com → 读 `meta[name="grok-site―verification"]` 得 Q、hook `crypto.subtle.digest` 输入解析得 SALT；随账号/会话缓存。
  - 签名（高频）：纯 Python 生成真签名，无需每次起浏览器。
  - 轮换：指纹失效时重取一次。

> **关于"SALT 能否纯算"的最新订正（2026-06-11 拼装层 / 2026-06-12 插值层，见逆向文档 §5.2.2、§5.2.3）**：此前判定"SALT=z(Q) 是 Chromium 渲染插值、纯 Python 算不出"。把签名 chunk 去混淆到原语级后发现，最唬人的拼装层（`…28f5c28f6…`）其实是 JS `Number.toString(16)` 浮点输出，已用 `salt_assembly.py` 逐字符复刻（B/C 两会话 EXACT）。随后又把 ④ transform 插值正向闭合：纯 Python 复刻 W3C cubic-bezier + 旋转 matrix，与 Chrome Web-Animations 的 computed matrix **逐位吻合到 6 位小数**，`currentTime=round(C/10)*10`，端到端 `build_z_suffix(row,C)` 对平凡/非平凡向量均 EXACT。结论修正为：**z(Q) 全链 ①③④⑤ 均纯算实证，唯一非纯算输入只剩 ② m 矩阵（运行时 SVG 图标 path），须每 build 提取一次**——故方案 ② 仍以"低频浏览器取指纹"为终态，但"纯算根本不可能"的旧定性已被彻底推翻。

---

## 6. 附：本机复现命令

```bash
cd docs/reverse
# 自测：验证真实算法能逐字符复刻浏览器真值 + 各兜底值
PYTHONUTF8=1 python x_statsig_id.py
# 预期：[core algo] PASS / [extracted] PASS / [x0 fallback] PASS
```
