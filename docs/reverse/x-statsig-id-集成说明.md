# x-statsig-id 真签名集成说明

> 配套逆向文档：`x-statsig-id-逆向分析.md`（算法逐字符验证）、`x-statsig-id-生成过程详解.md`、
> `x-statsig-id-算法对比.md`、`salt_assembly.py`（z(Q) 末三层纯算闭合）。

## 1. 这次集成做了什么

把已逐字符验证的 **纯 Python `x-statsig-id` 真签名算法** 落地到生产代码，作为现有
x0 兜底之外的可选升级路径。核心策略：

> **配齐指纹走真签名，缺失 / 异常自动回退 x0 兜底。** 开箱即用，配置后自动升级。

- 留空配置 = 维持现状（官方 x0 兜底，当前 build 实测可用）。
- 配置一组全局指纹 `(Q, SALT)` = 全局升级为 94 字符真签名。

## 2. 算法回顾（已验证）

```
timeFactor   = floor(now/1000) - 1682924400
message      = "{METHOD}!{pathname}!{timeFactor}" + SALT
digest       = SHA-256(message)                              # 32B
payload(70B) = [r] + Q(48) + uint32LE(timeFactor)(4) + digest[:16](16) + [3]
out          = payload[0] 之外全部 XOR 随机头 r
x-statsig-id = base64(out).rstrip("=")                       # 94 字符
```

- **Q**：48 字节设备指纹 = `atob(<meta name="grok-site―verification">.content)`，SSR 下发。
- **SALT** = `"obfiowerehiring"` + `z(Q)`。`z(Q)` 是浏览器渲染指纹，但本仓库逆向已证明
  其末三层（color 插值 / transform cubic-bezier 矩阵 / 浮点拼装）均可纯 Python 复刻，
  唯一非纯算输入是 build 常量级别的 m 矩阵（详见 `salt_assembly.py` 与逆向文档 §5.2.3）。
- 生产取指纹方式：浏览器读 meta 得 Q、hook `crypto.subtle.digest` 读明文输入取 SALT。
  与 `cf_clearance` 同构 —— build 常量级别，发新构建后失效需重取一次。

## 3. 代码改动

| 文件 | 改动 |
|---|---|
| `app/dataplane/proxy/adapters/statsig.py` | **新建**。真签名 `gen_x_statsig_id` + `x0_fallback` + 指纹解析 `resolve_statsig_fingerprint` + 顶层路由 `statsig_id(method, pathname)` |
| `app/dataplane/proxy/adapters/headers.py` | `_statsig_id` 委托给新模块；`build_http_headers` 新增 `method`/`pathname` 参数；清理死 import |
| `app/dataplane/reverse/transport/http.py` | 5 个 transport 函数（post_stream / post_json / get_json / delete_json / get_bytes_stream）从 `url` 解析 pathname、按语义注入 method |
| `app/products/openai/chat.py` | `_stream_chat` 直连 `CHAT` 处注入 `method="POST", pathname=CHAT_PATH` |
| `app/products/openai/images.py` | 2 处直连 `CHAT` 注入真签名 |
| `app/products/openai/video.py` | 直连 `CHAT` 注入真签名 |
| `app/dataplane/reverse/transport/asset_upload.py` | 上传端点注入真签名；GET 外部图床 URL 保持兜底（非 grok 端点） |
| `app/dataplane/reverse/runtime/endpoint_table.py` | 新增 `CHAT_PATH` 常量（与 `CHAT` url 同步） |
| `config.defaults.toml` | 新增 `[statsig]` 段 |
| `tests/test_statsig_id.py` | 重写：覆盖真签名黄金向量、兜底、指纹解析、headers 委托 |

### 设计决策

1. **注入点选择**：`http.py` 的 5 个 transport 函数都已持有 `url`，是覆盖面最广的注入点；
   chat/images/video/asset-upload 几处绕过 transport 的直连 `CHAT` 单独注入。这覆盖了所有
   主要 API 流量。
2. **grpc_web / livekit 保持兜底**：异主机端点（accounts.x.ai）+ 边缘功能，statsig 校验严格度
   未实测，保守不注入，避免对未验证路径引入风险 —— 符合「失败回退兜底」整体策略。

## 4. 配置方式

```toml
[statsig]
# 模式：real（优先真签名，缺指纹自动回退兜底）| fallback（强制 x0 兜底）
mode = "real"
# 48 字节设备指纹 Q 的 base64（浏览器读 meta[name="grok-site―verification"]）
q = ""
# 完整 SALT（obfiowerehiring + z(Q)）或仅 z(Q) 后缀（自动补前缀）
salt = ""
```

**留空 = 现状**（x0 兜底）。填入一组指纹即全局升级真签名。

## 5. 端到端实测（60 次轮询）

在已过 Cloudflare 的浏览器环境中，用本算法 + 一组真实指纹现场生成签名（每次全新
timeFactor + 随机头 r，与页面自发签名互不相同），对 5 个账号轮询发起 60 次真实
`POST /rest/app-chat/conversations/new`：

| 指标 | 结果 |
|---|---|
| 总请求 | 60 |
| **签名通过率** | **60 / 60 = 100%** |
| Cloudflare 拦截 | 0 |
| statsig 拒绝 | 0 |
| HTTP 200（成功创建会话） | 32 |
| HTTP 429（账号配额用尽，签名已通过） | 28 |

> 429 是账号配额耗尽（错误 code 8 "heavy usage"），请求已穿过 CF + statsig 校验抵达配额
> 计费层 —— 即签名被服务端接受。5 账号 `other`（非 200/429 失败）全为 0。

**结论**：纯算真签名 60 次零失败穿过 Cloudflare + statsig 校验。

## 6. 单元测试

`tests/test_statsig_id.py`，16 个用例全 PASS：

- **真签名黄金向量**：给定相同 tf/r，逐字符等于浏览器真实采样值。
- 签名长度恒为 94；Q 长度非 48 抛错。
- x0 兜底：静态值解码为 `x0:TypeError...childNodes`；动态值 `x0:` 前缀。
- 指纹解析容错：缺字段 / base64 错 / 长度错 → 返回不完整指纹（上层回退兜底）；
  SALT 仅后缀时自动补 `obfiowerehiring` 前缀。
- 顶层路由：配齐走真签名；缺指纹 / 无上下文 / mode=fallback → 兜底。
- headers 委托：`build_http_headers` 透传 method/pathname。

运行：

```bash
python -m pytest tests/test_statsig_id.py -v
# 或
python -m unittest tests.test_statsig_id -v
```
