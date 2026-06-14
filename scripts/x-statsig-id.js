#!/usr/bin/env node
/**
 * x-statsig-id.js —— grok.com `x-statsig-id` 请求头签名器(零浏览器 / 补环境方案)
 * ---------------------------------------------------------------------------
 * 原理:把 grok 当前 build 的**原版签名模块** sig_live.js 直接在 Node 里跑,
 *      只补 document / element.animate / getComputedStyle 等浏览器原语
 *      (getComputedStyle 的 transform/color 用 W3C cubic-bezier + rotate 矩阵
 *       数学顶上,与 Chrome 逐字节等价)。行索引 O、currentTime、path 解析全部
 *      由 grok 原码自算 —— grok 改版改索引/公式都不用动这里。
 *
 * 实测(2026-06-15):
 *   - 对同一 (Q,tf,r) 逐字节复刻 grok 浏览器真实签名;
 *   - grok-4.20-fast POST /rest/app-chat/conversations/new:补环境签名 0×403,
 *     垃圾签名对照组 403 code7。
 *
 * 依赖:仅 Node 内置(>=18:全局 fetch / net / tls / webcrypto)。无需浏览器、无 npm 包。
 *      grok 原版签名 chunk 已 base64 内嵌(SIG_CHUNK_B64)—— 真·单文件,可直接拷走运行。
 *
 * ── 每次 grok 发版需更新两样 build 常量(都在本文件里)──
 *   1) SIG_CHUNK_B64 : grok 签名 chunk 的 base64。浏览器里搜 base64 解码器特征定位
 *                      chunk → save_script_source 存为 sig_live.js → 重新生成:
 *                        node -e 'c=require("fs").readFileSync("sig_live.js","utf8");\
 *                          s=require("fs").readFileSync("x-statsig-id.js","utf8");\
 *                          require("fs").writeFileSync("x-statsig-id.js",\
 *                          s.replace(/const SIG_CHUNK_B64 = "[^"]*"/,\
 *                          "const SIG_CHUNK_B64 = "+JSON.stringify(Buffer.from(c).toString("base64"))))'
 *                      或调试期设 STATSIG_CHUNK=./sig_live.js 用外部文件免重嵌。
 *   2) M_PATHS       : 页面 `.r-XXXX` 4 个 svg 的 path d(本文件下方常量)。
 *      抓法:浏览器 querySelectorAll(选择器)→ 每元素 .childNodes[0].childNodes[1].getAttribute('d')。
 *   ⚠️ 选择器名(.r-3gp4f0)与 chunk 每次发版都变,M_PATHS 几何稳定。
 *
 * 用法:
 *   // 作为模块
 *   const { createSigner, fetchQ } = require('./x-statsig-id.js');
 *   const sign = await createSigner();                  // 加载一次
 *   const q   = await fetchQ({ proxy: 'http://127.0.0.1:7897', cookie: 'cf_clearance=…' });
 *   const sig = await sign('/rest/app-chat/conversations/new', 'POST', q);
 *
 *   // 命令行(注意 Git-Bash 需 MSYS_NO_PATHCONV=1 防止 /rest 被转成 Windows 路径)
 *   MSYS_NO_PATHCONV=1 node x-statsig-id.js /rest/app-chat/conversations/new POST <Q>
 */
"use strict";
const fs = require("fs");
const nodeCrypto = require("crypto");

// ===========================================================================
// build 常量(发版需更新)
// ===========================================================================
const ANIM_DURATION = 4096;
const DEFAULT_PROXY = process.env.HTTPS_PROXY || process.env.ALL_PROXY || "";
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
           "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36";

// `.r-3gp4f0` 的 4 条 svg path d(grok 用 Q[5]%4 选其一作 m 矩阵源)。
const M_PATHS = [
  "M 10,30 C 6,66 238,95 164,64 h 89 s 88,232 143,153 C 137,87 5,145 114,180 h 46 s 54,169 78,35 C 234,140 0,112 134,95 h 233 s 249,77 165,59 C 38,204 162,180 220,121 h 6 s 3,187 131,171 C 69,195 222,105 123,153 h 139 s 24,225 152,159 C 125,215 201,40 69,218 h 49 s 229,150 201,81 C 222,187 191,131 38,226 h 77 s 90,15 200,103 C 226,104 242,81 178,86 h 78 s 110,131 62,88 C 146,227 0,58 60,245 h 236 s 98,120 68,222 C 96,126 11,115 251,229 h 123 s 208,42 179,131 C 38,16 12,183 162,119 h 167 s 26,49 121,244 C 58,238 5,86 235,43 h 54 s 227,112 150,195 C 85,91 37,160 122,144 h 149 s 169,214 10,52 C 152,49 80,91 3,197 h 141 s 198,173 118,35 C 135,108 221,3 236,30 h 123 s 71,10 178,178 C 222,56 194,176 196,15 h 85 s 241,255 217,218",
  "M 10,30 C 148,127 93,6 146,40 h 128 s 22,88 136,28 C 18,106 247,51 104,28 h 48 s 163,77 5,196 C 205,76 239,178 173,47 h 193 s 112,121 40,200 C 225,203 74,37 246,76 h 0 s 0,215 153,121 C 51,156 83,58 120,194 h 112 s 198,37 0,158 C 78,150 56,192 178,44 h 201 s 103,71 137,236 C 167,41 85,225 52,79 h 239 s 25,197 124,253 C 200,85 181,212 114,92 h 100 s 249,14 246,104 C 30,208 239,2 146,247 h 200 s 158,192 211,35 C 100,48 189,82 101,206 h 186 s 86,70 215,222 C 227,192 31,6 20,210 h 196 s 81,216 36,181 C 81,168 144,175 233,187 h 104 s 134,43 47,149 C 211,204 85,247 118,233 h 36 s 223,170 116,114 C 15,98 62,151 12,194 h 23 s 26,139 28,117 C 81,3 110,188 44,40 h 140 s 70,102 170,146 C 194,230 211,204 100,58 h 181 s 117,107 2,51",
  "M 10,30 C 61,171 246,30 203,246 h 142 s 140,103 47,244 C 173,110 139,45 222,46 h 6 s 105,56 255,109 C 33,223 62,63 174,5 h 5 s 62,12 253,8 C 34,79 58,159 75,27 h 172 s 86,152 89,117 C 211,174 51,117 107,199 h 58 s 87,140 39,169 C 143,228 129,100 79,29 h 11 s 77,109 94,194 C 165,93 51,134 69,217 h 234 s 143,200 22,212 C 19,54 86,219 78,26 h 107 s 25,118 145,159 C 152,201 115,102 32,143 h 150 s 196,75 13,112 C 111,207 43,208 93,120 h 15 s 204,182 142,55 C 122,106 250,81 141,177 h 172 s 65,76 67,242 C 181,86 243,226 19,170 h 193 s 131,203 67,45 C 120,144 215,45 180,42 h 140 s 88,41 238,78 C 89,168 33,173 146,142 h 42 s 234,219 194,47 C 67,32 66,153 119,198 h 179 s 33,75 64,18 C 86,95 175,18 69,174 h 153 s 229,109 57,49",
  "M 10,30 C 182,70 123,45 229,114 h 50 s 188,203 172,70 C 247,86 52,225 44,199 h 87 s 142,249 73,234 C 98,163 0,173 229,26 h 199 s 63,61 154,55 C 230,1 44,222 246,80 h 206 s 39,14 119,189 C 167,165 163,230 39,163 h 225 s 79,170 185,108 C 125,253 163,129 205,53 h 19 s 59,112 222,33 C 6,95 79,244 128,140 h 209 s 32,202 12,48 C 148,125 28,59 59,8 h 82 s 7,97 199,226 C 69,209 29,18 255,208 h 17 s 243,224 118,76 C 93,192 66,168 208,0 h 90 s 200,19 30,216 C 157,59 108,98 137,166 h 254 s 205,52 230,164 C 183,141 20,6 195,36 h 121 s 246,183 7,104 C 112,1 52,175 20,126 h 98 s 144,205 161,194 C 140,31 41,107 53,187 h 6 s 237,25 143,45 C 248,118 106,16 161,191 h 0 s 184,20 252,221 C 128,202 251,139 51,141 h 66 s 251,117 193,202",
];

// ===========================================================================
// getComputedStyle 矩阵数学(Chrome 等价:cubic-bezier easing + rotate + 颜色插值)
// ===========================================================================
const jsRound = (x) => Math.floor(x + 0.5);

function cubicBezier(x1, y1, x2, y2) {
  const A = (a, b) => 1 - 3 * b + 3 * a, B = (a, b) => 3 * b - 6 * a, C = (a) => 3 * a;
  const calc = (t, a, b) => ((A(a, b) * t + B(a, b)) * t + C(a)) * t;
  const slope = (t, a, b) => 3 * A(a, b) * t * t + 2 * B(a, b) * t + C(a);
  const tForX = (x) => {
    let t = x;
    for (let i = 0; i < 8; i++) { const s = slope(t, x1, x2); if (s === 0) break; t -= (calc(t, x1, x2) - x) / s; }
    let lo = 0, hi = 1, tt = x; if (t < lo) t = lo; if (t > hi) t = hi;
    for (let i = 0; i < 12; i++) { const xv = calc(tt, x1, x2); if (Math.abs(xv - x) < 1e-7) return tt; if (xv < x) lo = tt; else hi = tt; tt = (lo + hi) / 2; }
    return t;
  };
  return (x) => (x1 === y1 && x2 === y2) ? x : calc(tForX(x), y1, y2);
}

const parseHexColor = (s) => { const m = /#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})/i.exec(s); return [parseInt(m[1], 16), parseInt(m[2], 16), parseInt(m[3], 16)]; };
const parseRotateDeg = (s) => parseFloat(/rotate\(([-\d.]+)deg\)/.exec(s)[1]);
const parseEasing = (s) => /cubic-bezier\(([^)]+)\)/.exec(s)[1].split(",").map(Number);

function computeStyle(kf, ct) {
  const [x1, y1, x2, y2] = parseEasing(kf.easing);
  const p = cubicBezier(x1, y1, x2, y2)(ct / ANIM_DURATION);
  const c0 = parseHexColor(kf.color[0]), c1 = parseHexColor(kf.color[1]);
  const clamp = (v) => Math.max(0, Math.min(255, v));
  const col = [0, 1, 2].map((i) => clamp(jsRound(c0[i] + (c1[i] - c0[i]) * p)));
  const rad = parseRotateDeg(kf.transform[1]) * p * Math.PI / 180;
  const cos = Math.cos(rad), sin = Math.sin(rad);
  return { color: `rgb(${col[0]}, ${col[1]}, ${col[2]})`, transform: `matrix(${cos}, ${sin}, ${-sin}, ${cos}, 0, 0)` };
}

// ===========================================================================
// 补环境:document / element / animate / getComputedStyle 的最小 stub
// ===========================================================================
let CURRENT_Q = null;

const makeSvg = (d) => ({
  childNodes: [{ childNodes: [null, { getAttribute: (n) => (n === "d" ? d : null) }] }],
  parentElement: { removeChild() {} },
});
const makeAnimEl = () => {
  const el = { __kf: null, __ct: 0, parentElement: { removeChild() {} } };
  el.animate = function (kf) {
    el.__kf = kf;
    return { _ct: 0, pause() {}, play() {}, get currentTime() { return this._ct; }, set currentTime(v) { this._ct = v; el.__ct = v; } };
  };
  return el;
};

function installEnv() {
  if (!globalThis.crypto || !globalThis.crypto.subtle) globalThis.crypto = nodeCrypto.webcrypto;
  globalThis.window = globalThis;
  globalThis.document = {
    querySelectorAll(sel) {
      if (typeof sel === "string" && /name/i.test(sel)) return [{ getAttribute: (n) => (n === "content" ? CURRENT_Q : null) }];
      if (typeof sel === "string" && sel.startsWith(".r-")) return M_PATHS.map(makeSvg);
      return [];
    },
    createElement: () => makeAnimEl(),
    documentElement: { append() {}, appendChild() {}, removeChild() {} },
    body: { append() {}, appendChild() {}, removeChild() {} },
    head: { append() {}, appendChild() {}, removeChild() {} },
  };
  globalThis.getComputedStyle = (el) => (el && el.__kf) ? computeStyle(el.__kf, el.__ct) : { color: "rgb(0, 0, 0)", transform: "none" };
  // grok 传小写 "sha-256",Node webcrypto 要大写
  const realDigest = globalThis.crypto.subtle.digest.bind(globalThis.crypto.subtle);
  globalThis.crypto.subtle.digest = (alg, data) => realDigest(typeof alg === "string" ? alg.toUpperCase() : alg, data);
}

// grok 原版签名 chunk(sig_live.js)base64 内嵌 —— 单文件自包含。发版时用新 chunk 重新生成。
const SIG_CHUNK_B64 = "OyFmdW5jdGlvbigpe3RyeSB7IHZhciBlPSJ1bmRlZmluZWQiIT10eXBlb2YgZ2xvYmFsVGhpcz9nbG9iYWxUaGlzOiJ1bmRlZmluZWQiIT10eXBlb2YgZ2xvYmFsP2dsb2JhbDoidW5kZWZpbmVkIiE9dHlwZW9mIHdpbmRvdz93aW5kb3c6InVuZGVmaW5lZCIhPXR5cGVvZiBzZWxmP3NlbGY6e30sbj0obmV3IGUuRXJyb3IpLnN0YWNrO24mJigoZS5fZGVidWdJZHN8fCAoZS5fZGVidWdJZHM9e30pKVtuXT0iZThjMTQwY2ItNDkzNS1mM2M5LWQxMjYtODc4MTQ2YmNkMzE0Iil9Y2F0Y2goZSl7fX0oKTsKKGdsb2JhbFRoaXMuVFVSQk9QQUNLfHwoZ2xvYmFsVGhpcy5UVVJCT1BBQ0s9W10pKS5wdXNoKFsib2JqZWN0Ij09dHlwZW9mIGRvY3VtZW50P2RvY3VtZW50LmN1cnJlbnRTY3JpcHQ6dm9pZCAwLDE2NDVlMyxXPT57InVzZSBzdHJpY3QiO2Z1bmN0aW9uIG4oKXtsZXQgVz1bIlc2bGNOOG8rV09GY0tXIiwibE00Z1c2M2RJYSIsImVTa0ZXNWhjVjhvcyIsImR0TEF4Y08iLCJnSkpkT0NrSFc2eSIsIng4a25XN2hkTDF1IiwiQ1NrL1c2eGROaEciLCJndGJ5eGM0IiwiamFTRFdSTmRLcSIsIno4bytrU29qV1BoY1VXTmNSU28yVzY5KyIsIm1zNDZXUlZkSUciLCJhSk9wVzdHIiwiVzdoZFBtb3pXUC9jS0ciLCJiVzdkTG1rUlc3VyIsIldPRmNPOGtrVzVmYSIsIldQZWNXNkZkTEciLCJvSUZkUThrYlc0MCIsImpTb0hXUm1pZG1raFc0bGNMTUMiLCJiQ2tPVzVwY1Vtb1QiLCJXN2xkUkNrbnhIUyIsIlc1RGtXUmlJV1JlIiwia1NvMUQybSIsIldPM2RNSDAiLCJXT0drV1BtdWJ3SmRVOG9kamEiLCJtWjg0V1EzZEdXIiwielNrd1c3cWxrcSIsImhxcGNUTHVTIiwiblNvRG84a0JFcSIsIldRbGNROGtIVzVQUiIsIldPSExXUkRlVzZPIiwiZUlsY0x4U2ciLCJXT2xkSGFKZFNDa2YiLCJXNmV1QU1wZElhIiwiV1BkZE9Da2VXNzluIiwiVzVKZFFDb0tXUi9jT1ciLCJXUjNjVnNhcldPbSIsIkFHWmROaEhUIiwiV09SZFZta2VXN1hKIiwiVzdmMWphIiwiVzVibFdSQmNUbW9uIiwiVzZGY09TbzlXUnBjS1ciLCJXTzlYV1F6aFc2dSIsIlc1MHZXNEt2V1JuNEVDb3ZDZXZkV1EvY0hxIiwiZDhvUkJ3RmRPYSIsImljbGNJWUczIiwiRFNrYldPVmNLdk8iLCJXN3I2V09DeldQaSIsIldPZGRMbWtTIiwiV1JoY0pKSyIsIlc2bm5XUTNjS21rbiIsIlc3OXdXTzNjTW1rdSIsIldQQmNNbW9TVzdMbCIsIlc3eGNJQ2trVzVOZElhIiwiVzZaZFE4bzZXUlJjSHEiLCJwQ293VzYvZFZHbSIsIlc2OTdqU29KcXEiLCJXN3JUV1IvY0w4a0MiLCJyU2tpV09KY0gxVyIsIldPL2RTclRYVzdHIiwiV080aldQanh3RzNkSVNvTGI4a0x5Q29QIiwiaG1veVc0dGRQV3UiLCJXUlJkTG1reVc2NTIiLCJXN0pjUjhrVFc3SmRHRyIsIldSTmNHc1JjUUttIiwiZFlYZ3lXIiwiVzdwY044b3VXT1JjSWEiLCJyOGtYQThvYmVHIiwiV1BCZEthcGNJTDgiLCJyU2tEQ3EiLCJXT2VpVzdwZEc4b0ciLCJXTzFvV1BEaVc2QyIsImhDbytudjU1IiwicGJaZEdTa3dGRyIsIm5keGNOY1dSIiwiZlNvUGJDa1dGVyIsIlc1SmNHU29aV09kY0xxIiwiVzVCY0plUmRMV1pjTThvT1c1NTdXUVZkTGEiLCJpSjdjSFlxSSIsImEyUmNNbWtoZGEiLCJsbW9UbUtYTCIsInZTa0l5WkswIiwiZkNvSGwzblIiLCJXUnZ2YWJwY1ZTby9zU29uV1B6Y1c1anMiLCJlYXRkVkNrR1c1eSIsIlc1ekVXNEszVzZxIiwiV09CZFVHSHNXN3UiLCJuYTArV1FGZElhIiwiZW1vaGVDa0xGcSIsIm90NGpXNXBkVkciLCJwYUpjTzBtUyIsIlc1N2NNU2ttVzd0ZElxIiwieUgvZFJHIiwiYnZyYmFabSIsInBtb1pXUUsxV1JtIiwiV09sZFFHNUhXNnEiLCJxQ2t2QThvaSIsImFtb21pU2tnQmEiLCJXUkJjSThrYVc1VGQiLCJvQ28rYnhiZyIsIkJta3NXT1BodFciLCJXUVZjTFpTdFdRNCIsIlc1aGRQSzAiLCJFdXRjTzhvcW8yL2NHOGtqV1AvY0dtb2FycmEiLCJpU29OV1JqaXZTb05XUTdjT3gwdmFDa2VXN2EiLCJXNHZYV09TIiwiV1JKY1VYN2NPTm0iLCJiV3BkVG1rSCIsIlc3THpXN2lPIiwiRG1vNHQzTmRSOG9PYkciLCJXNkQra0NvMEJXIiwiV1JCY0o4a2dXNHJjIiwiaGdQZm1IdSIsImltb21XT3BkS1ciLCJXT2xkUnJMWVc3dSIsIkNta0xnRyIsIldPTmRMYW0iLCJxQ2tDQlNvaWdXIiwicmhKY1BDa0FnQ29NRlciLCJlWjhvVzZaZFNhIiwiZ2NieHFjVyIsIldRN2NKSUZjT3VHIiwiVzRmaldQR0FXUTgiLCJXNDVGVzVhIiwiZG1vNVdPaGRWWXEiLCJCYVZkVmY1aSIsIkRDazJ1OG9NZWEiLCJDQ2tLRWNuSiIsIldQWmNHOGtSVzVUKyIsInFzL2RHOG9FdENrWGlaZkVXUjVPVzY4biIsIldRUmRHV1JkVlNrSiIsIlc0TEJXUHVqV1BtIiwibzhrVkJXIiwiVzY5SldPZGNRQ29CIiwiVzZMWFdPUyIsIlc1R3hXNEt2V1I0ZG04b2t3MlBRIiwiVzRXMFdPN2NNU284IiwicW1rUGNaZGNJYSIsIlc2N2RUQ280V1JOZFZHIiwiV1FKZExhbGNVRyIsIm1nVGFtbW90IiwiQkNrNFdPdmx1YSIsIldQaGRScm5OVzY0IiwicDhrelc1WmNWbW9SIiwiVzQ3Y1I4b3BXUXBjUVciLCJhdWpNY0NvaSIsIkRTa2ZwWFZjS0ciLCJXN0h0VzdpeGxhIiwiV1Fhc1c2WmRHU29hV1B2Nlc3L2NRZkxaIiwiV08vZFZibjNXNnEiLCJXUnBkSVo5ZFc2cSIsImdjYnhyWnEiLCJXNkpjUVNrUCIsInFta1JjdHRjU0ciLCJXNGhjVDhrU1c1TmRVcSIsIlc2ZlRXTzBtV1E0Iiwib21vK1dSeVkiLCJXN0JjUjhrUCIsIlc0L2RTOG9mV1JOY1RhIiwiaVNrSHdDa3RXNWEiLCJXT2FEVzYvZEhTbzEiLCJnU290V1FTcldROCIsIldQVmNIU2s1VzZEaiIsIldQeWRXN0MiLCJXNS9kR3gzZE9Db1UiLCJjU29nV1JpUFdQcSIsImJDb1FhQ2tXQnEiLCJXN2hkU01OZFM4b2siLCJpY1cvV09OZFJhIiwiV1BIcFdSSG1XNzQiLCJXUXhjR3EvY05nVyIsImttbytqTGZaIiwiV090ZFNxRyIsImVTazZXNi9jTkNvaCIsIldPTmNVci9jU1NrQVc3cTFXNVpkR21vYUZiUmNIRyIsInpTa1pBd2lrIiwic0NrU3pHIiwiVzRLRVdRaSIsIldPWmNSSk5jUWY4IiwiVzV4ZFVDbzFXUk5jUlciLCJqQ29SVzRGZExyUyIsImVDby9seDFzIiwiV1EvY0dZZGNQS2kiLCJXNmxjR1NvcldPWmNORyIsImNjRHF1SVciLCJXNnVwdTFkZEpXIiwiQVNrV1dQem5zVyIsImFtb3JXNXBkSUciLCJoU29uVzdKZEtYbSIsInFMUmNQbW82V1BmRWpDa0RDWmxjUDhrUFdSRyIsIm5tb0hXT1pkSkp1IiwiV1JkY084a29XNVhoIiwiaVhOZFZTa0lXNDAiLCJFQ2tXV1BiRHJHIiwiVzdOY1U4ay9XNzNkSlciLCJXNDdkSXdkZEhtb1EiLCJzWC9kUUxpIiwib1hhaFdQUmRIcSIsIm84b2ZlZkxiIiwiVzZQTldSYS9XT20iLCJXNW1lV1JGY1Ztb2EiLCJXT0ttV1BEd3VocGRNU29DaUNrenFHIiwiVzRqc1c1bXdXNmUiLCJXNW5mV1FCY1VxIiwiclNrd1dQN2NIZTAiLCJlU29KaW1rc0FXIiwiV1B4ZEdTa1pXN2EiLCJiQ282YVNrdXVhIiwiVzRyeFdQcUVXUWEiLCJuU29WbENreHRxIiwiRVNrSFdPNWh2VyIsIlc1ZlFXUE9GV1E0Iiwidm1rU3pkaSsiLCJwYkRIQ3RDIiwiVzdKZFBta1p6YkciLCJvWnRjVHVDKyIsIkU4a1ZXNFZkT2VpIiwiczhrRnkyUzIiLCJXNlBiV1FoY1BxIiwiZW1rN0NDa3pXNVciLCJXUXRjUm1vTFdQRmNIVyIsIm44a0dEU2t4VzRLIiwiVzR5NldSeGNTbW9NIiwiV1BMS1dRVEdXN2kiLCJmOG9PVzY3ZEhHSyIsImpHRmRIQ2tseXEiLCJXN3pSV083Y0w4azQiLCJXNTVqVzR1aGhhIiwiZVpXcFc3WmRUYSIsIlc1cUxXUGxjU1NvQiIsIlc3ZGNHbWt1VzUvZElXIiwibWIvY1BMNGgiLCJXUHZvV1JIOFc0MCIsIlc3TFlmU29CQmEiLCJCbWtKVzRPIiwiVzV2SmVDb2RDYSIsImhhL2RUbWtvVzVhIiwieVNrdUNNT1kiLCJsWEJkUENrSHlXIiwieW1rL1dPdSIsImpjV0pXUm0iLCJXNTNkUzhvS1dRYSIsIlc0NXRXNGZsd0ciLCJoRzFydXNXIiwibkNvSWlhIiwicVNrc1c3aXRjVyIsIlc3N2NQQ2tiVzRKZEhHIiwiVzV4ZFVmL2RTOG9rIiwiVzVWZFZDa293ckMiLCJXNzdkR0NrcnhIeSIsImZJN2RWQ2tRVzRLIiwiV1A0bVc3bSIsInFDa010R3E4IiwibVNvcldQbGRWc3EiLCJsOG9HbExYTCIsIldQYWNXNjNkSm1vRyIsIldSSmRJYnhkVEciLCJ1OGs0V09uZkFhIiwiem1vM2pTb2xXUFJjT3QzY0tTb1dXNFBvIiwiQkpsY0labVEiLCJuWi9jTmFHViIsIldQM2ROU2s3Vzc5eCIsIkZDa1lXN3l0ZEciLCJmbW80YjhrTURHIiwibG1vN1c2N2RPSUMiLCJXUVBYV1FyY1c3dSIsImlTa3pXNTNjSzhvbSIsImRDb0VuSzVYIiwiVzZ6VVc3OEtXNXEiLCJqYk5jVXM4YyIsIndTay9XNUtHY2EiLCJhbWtzVzVwY05tb04iLCJXN05kUlNvYVdPUmNMcSIsIlc2WmRVbWtLcVdhIiwibjBmU204b2oiLCJlM3hjTVNrQWhxIiwiV1AvY1ZzbSIsIlc2VEdXT0ZjTG1vayIsIkRTazdDTW1CIiwiRlNrUkQybXEiLCJXN1hkV1FLIiwiVzVhOFdRN2NIU29RIiwicDhrREU4a3RXNmkiLCJXNnV2djBwZFVhIiwibkNvK2xMZk4iLCJwSmkzVzVkZFVHIiwiV1FKY0diUmNTdnUiLCJpU2tKVzRSY0lDbzEiLCJXNkRaVzdDSlc0MCIsIldSeGNOWWxjU3hhIiwidVNrMlc3ZGRLeDQiLCJXT1pkVkdIV1c2SyJdO3JldHVybihuPWZ1bmN0aW9uKCl7cmV0dXJuIFd9KSgpfWZ1bmN0aW9uIHQoVyxjKXtsZXQgcj1uKCk7cmV0dXJuKHQ9ZnVuY3Rpb24obixjKXtsZXQgbz1yW24tPTE2OV07aWYodm9pZCAwPT09dC5JTERCU24pe3ZhciBlPWZ1bmN0aW9uKFcpe2xldCBuPSIiLHQ9IiI7Zm9yKGxldCB0PTAsYyxyLG89MDtyPVcuY2hhckF0KG8rKyk7fnImJihjPXQlND82NCpjK3I6cix0KyslNCkmJihuKz1TdHJpbmcuZnJvbUNoYXJDb2RlKDI1NSZjPj4oLTIqdCY2KSkpKXI9ImFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5Ky89Ii5pbmRleE9mKHIpO2ZvcihsZXQgVz0wLGM9bi5sZW5ndGg7VzxjO1crKyl0Kz0iJSIrKCIwMCIrbi5jaGFyQ29kZUF0KFcpLnRvU3RyaW5nKDE2KSkuc2xpY2UoLTIpO3JldHVybiBkZWNvZGVVUklDb21wb25lbnQodCl9O3QuV0dSdWtNPWZ1bmN0aW9uKFcsbil7bGV0IHQsYz1bXSxyPTAsbyx1PSIiO2Zvcih0PTAsVz1lKFcpO3Q8MjU2O3QrKyljW3RdPXQ7Zm9yKHQ9MDt0PDI1Njt0Kyspcj0ocitjW3RdK24uY2hhckNvZGVBdCh0JW4ubGVuZ3RoKSklMjU2LG89Y1t0XSxjW3RdPWNbcl0sY1tyXT1vO3Q9MCxyPTA7Zm9yKGxldCBuPTA7bjxXLmxlbmd0aDtuKyspcj0ocitjW3Q9KHQrMSklMjU2XSklMjU2LG89Y1t0XSxjW3RdPWNbcl0sY1tyXT1vLHUrPVN0cmluZy5mcm9tQ2hhckNvZGUoVy5jaGFyQ29kZUF0KG4pXmNbKGNbdF0rY1tyXSklMjU2XSk7cmV0dXJuIHV9LFc9YXJndW1lbnRzLHQuSUxEQlNuPSEwfWxldCB1PW4rclswXSxkPVdbdV07cmV0dXJuIGQ/bz1kOih2b2lkIDA9PT10LkxwaG5IYyYmKHQuTHBobkhjPSEwKSxvPXQuV0dSdWtNKG8sYyksV1t1XT1vKSxvfSkoVyxjKX0hZnVuY3Rpb24oVyl7bGV0IG49VygpO2Zvcig7Oyl0cnl7aWYocGFyc2VJbnQodCgzMzYsIjdDUXoiKSkvMSstcGFyc2VJbnQodCgxODYsIjdDUXoiKSkvMitwYXJzZUludCh0KDI4NiwiMnAlTiIpKS8zKigtcGFyc2VJbnQodCgzODUsIjJwdHIiKSkvNCkrLXBhcnNlSW50KHQoMzc5LCJGYSN2IikpLzUrLXBhcnNlSW50KHQoNDUwLCJlKUB5IikpLzYrcGFyc2VJbnQodCgzMTksInlbaEIiKSkvNytwYXJzZUludCh0KDM1Mywiek03OSIpKS84KihwYXJzZUludCh0KDI5NCwiNWg1SSIpKS85KT09PTE5NTEwNSlicmVhaztuLnB1c2gobi5zaGlmdCgpKX1jYXRjaChXKXtuLnB1c2gobi5zaGlmdCgpKX19KG4pLFcucyhbImRlZmF1bHQiLDAsKCk9PntsZXQgVyxuPSJ4b1BeIixjPSJhYTMjIixyPSJnVnolIixvPSJDT3pbIixlPSJCeGluIix1PSJlKUB5IixkPSJDT3pbIixpPSJ4b1BeIixmPXt0VVdndTpmdW5jdGlvbihXLG4pe3JldHVybiBXKG4pfSx1WGRidDpmdW5jdGlvbihXLG4pe3JldHVybiBXKG4pfSxmSnBlSDpmdW5jdGlvbihXLG4pe3JldHVybiBXJW59LG5HU0JiOmZ1bmN0aW9uKFcsbil7cmV0dXJuIFc9PT1ufSx5bkZZSzp0KDMxNCwiayheSCIpLGNhcnNnOnQoMzQ1LCJadkhuIiksbm5nYnk6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVyE9PW59LGJ4d3BzOnQoMzE3LG4pLHhkemRLOnQoNDQ5LCJCeGluIiksdURVRXQ6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVyhuKX0sblp1ZUM6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVypufSxaaWFrSzpmdW5jdGlvbihXLG4pe3JldHVybiBXL259LEtuV0xLOmZ1bmN0aW9uKFcsbil7cmV0dXJuIFcrbn0sWEJYRk06ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVy9ufSx2QmtkWTpmdW5jdGlvbihXLG4pe3JldHVybiBXKm59LG5idmlvOmZ1bmN0aW9uKFcsbil7cmV0dXJuIFctbn0sSnhPUlQ6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVyhuKX0sanROd3k6dCgxOTAsYyksSEJ0TXM6dCgyNjYsImRpTSUiKSxpcGt0VzpmdW5jdGlvbihXLG4pe3JldHVybiBXK259LFdCVEJvOmZ1bmN0aW9uKFcsbil7cmV0dXJuIFcqbn0saVNkaUo6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVyhuKX0sRWhScUQ6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVyVufSxla1hTbDpmdW5jdGlvbihXKXtyZXR1cm4gVygpfSxFRnVNaTpmdW5jdGlvbihXLG4pe3JldHVybiBXIT09bn0sT3Fzam46dCgyOTcsIio4RVMiKSxJTHpOaTp0KDE5NCxjKSxhVmd3eDp0KDQ1NywiVSokSyIpLHFHUnhlOnQoMzA2LCJ5W2hCIiksa05NRGE6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVyVufSxwYnZzdTpmdW5jdGlvbihXLG4pe3JldHVybiBXJW59LENVTFhhOmZ1bmN0aW9uKFcsbil7cmV0dXJuIFcvbn0sYnNXQks6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVz09PW59LHZBSkNFOnQoMjU4LCJ5ekIkIiksSXpDdGU6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVyE9PW59LGNRWGJjOmZ1bmN0aW9uKFcsbil7cmV0dXJuIFcqbn0sWnl1QlM6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVyVufSxkVFdnVDpmdW5jdGlvbihXLG4pe3JldHVybiBXJW59LEZRWmdzOmZ1bmN0aW9uKFcsbil7cmV0dXJuIFclbn0saURqZEQ6ZnVuY3Rpb24oVyxuLHQpe3JldHVybiBXKG4sdCl9LFJEZXlmOnQoMTg3LCJ5W2hCIikrdCgzNDEsIl0pXlYiKSxkSGtzdzpmdW5jdGlvbihXLG4sdCxjKXtyZXR1cm4gVyhuLHQsYyl9LEVUVW9jOmZ1bmN0aW9uKFcsbil7cmV0dXJuIFcobil9LGxES09SOmZ1bmN0aW9uKFcsbil7cmV0dXJuIFctbn0sSW1oTGs6ZnVuY3Rpb24oVyl7cmV0dXJuIFcoKX0sSnlCU1Q6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVyhuKX0sUUJyaWo6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVyhuKX0sSW9ZWmk6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVytufSxGcmVuYzp0KDI5NiwieXpCJCIpK3QoMzUwLCJhdDJUIikrdCgyNjksIlUqJEsiKSxjTnppYjpmdW5jdGlvbihXLG4pe3JldHVybiBXKipufX0sW2Esa109W2RvY3VtZW50LHdpbmRvd10sW1MseCxtLEMsUixsLE8sRyxQLEgsYixCLGhdPVtrW3QoMzA4LCJQVDZqIikrInIiXSxrW3QoMzIzLCIqOEVTIikrVSgtMjI5LHIsLTMxNywtMzI3LC00MjUpKyJyIl0sa1skKC01OSwyMCwtNjEsInhqNGIiLC03MikrXygiKjhFUyIsNzk3LDkxNiw4MTIsODY1KV0sVz0+YVt0KDE5NiwiKjhFUyIpK3QoMzIyLCIyN2JlIikrXygiYXQyVCIsNTA3LDYyOSw2MjYsNjI1KSsibCJdKFcpLGtbdCgxODEsIipnRFAiKV0sa1t0KDQwMywiOGNRZSIpK3QoMjA1LCJ4b1BeIikrInkiXSxrWyQoLTM4MywtNDExLC0zNTcsIjI3YmUiLC0yOTcpKyJvIl1bdCg0MjcsIlZpcm4iKSsiZSJdLGtbXygiVSokSyIsNzAxLDY0MCw3MjksNjUyKV1bdCgxOTEsImsoXkgiKV0sa1skKC0zNjAsLTQxNiwtMzg4LCIzRTZeIiwtMjk4KV0sa1t0KDQyNixyKSt0KDM0MixuKSskKC05NCwtNzEsMTA3LCJ4ajRiIiwtMzEpKyJvbiJdLGtbJCgtMjk1LC0yNDUsLTIxMywiNyV2ISIsLTMwOSkrInNlIl0sa1t0KDIwNCwiMnAlTiIpKyQoLTI2MCwtMTU3LC0zMDAsInpNNzkiLC0xODcpXSxrWyQoLTIwNywtMTQzLC00MDgsIkZhI3YiLC0yNjMpK3QoMjMyLCJlKUB5IikrVSgtNTMxLCJ4MTlhIiwtNDU4LC0zODksLTUxOCkrImUiXV0sUT1XPT5idG9hKEcoVylbdCgyNjUsIkZbJUgiKV0oVz0+U3RyaW5nW1UoLTIxNywiUFQ2aiIsLTQ4MiwtMzQ2LC0yMTYpK1UoLTMwMCwiejRsNiIsLTQ5NCwtNDE1LC0zNjIpKyJkZSJdKFcpKVt0KDQzMiwiIWpjUiIpXSgiIikpW3QoMzQ2LCIlXiZzIikrImNlIl0oLz0vZywiIikscz0oKT0+bmV3IG0oYXRvYihMKEModCgyMDIsIjRGZWMiKSt0KDI3OCwiWk5jZyIpKVswXSx0KDI2MCwiZFdSeCIpKyJudCIpKVt0KDE5NSwiJkxqISIpXSgiIilbdCgzOTIsInpNNzkiKV0oVz0+V1tVKC01MTEsIlhAcUoiLC01NjksLTU4MiwtNjkxKSskKC0yNzUsLTIxNywtMzMyLCI3JXYhIiwtMjY1KV0oMCkpKSxLPShuLGMpPT5XPVd8fEwoeihDKG4pKVtjWzVdJTRdW3QoMzkzLCJadkhuIikrdCgzMTYsIjNFNl4iKV1bMF1bdCgzODcsImMjMkgiKSt0KDM1MiwieG9QXiIpXVsxXSwiZCIpW3QoMzk2LCJWaXJuIikrdCgyODgsIlpOY2ciKV0oOSlbdCg0MzYsIiVeJnMiKV0oIkMiKVt0KDQ1MiwiOGNRZSIpXShXPT5XW3QoMzQ0LCJ6TTc5IikrImNlIl0oL1teXGRdKy9nLCIgIilbdCgyMjUsIngxOWEiKV0oKVt0KDM1NSwiZFdSeCIpXSgiICIpW3QoMzI1LCJLJSpXIildKFMpKSxMPShXLG4pPT5XJiZXWyQoNywtMTk5LC00NywiZ1Z6JSIsLTEyNCkrdCgyNzcsInhvUF4iKSsidGUiXShuKXx8IiIscD1XPT50eXBlb2YgVz09dCgxODUsImRpTSUiKSsiZyI/bmV3IHgoKVt0KDM0MCwiSyUqVyIpKyJlIl0oVyk6VyxOPVc9Pk9bJCgzMSwtMTU2LC00MCwiJkxqISIsLTY5KSsidCJdKHQoMjI3LCI3Q1F6IikrIjU2IixwKFcpKSxxPVc9PihXPDE2PyIwIjoiIikrV1tVKC01NzUsIkslKlciLC01OTcsLTQ4MSwtNTU2KSt0KDQ1MywiZGlNJSIpXSgxNiksej1XPT5HKFcpW3QoMzY4LCIqZ0RQIildKFc9PihXW3QoMTk3LCI4Y1FlIikrdCgyNzMsIkFIaUwiKSt0KDQ0OCwiZ1Z6JSIpXT8uW3QoMjg0LCJWaXJuIikrdCgzNzYsIiZMaiEiKSsiZCJdKFcpLFcpKSxnPSgpPT57ZnVuY3Rpb24gVyhXLG4sYyxyLG8pe3JldHVybiB0KHItNTc4LSAtNzUyLG8pfWZ1bmN0aW9uIG4oVyxuLGMscixvKXtyZXR1cm4gdChXLTEwMzUtIC03NTIsYyl9aWYoZltXKDExMCw4NCwxNTMsMTU1LCJDT3pbIildKGZbVygxNCwxOSwxNzIsNDMsInlbaEIiKV0sZltXKDEzNCwxNjMsMjM4LDI3MiwiSyUqVyIpXSkpe2xldCBXPWFbbig2MDQsNjMyLCJhdDJUIiw0NzcsNTA0KSt0KDIzNSwiNyV2ISIpK3QoMzgxLCIqOEVTIildKGZbVSgtODM1LCJ4MTlhIiwtMTA1NywtNDUxLC04MTUpXSk7cmV0dXJuIGFbbig1NzUsNjg0LCIlXiZzIiw0NzUsNzE5KV1bdCgyODcsIngxOWEiKSsiZCJdKFcpLFtXLCgpPT56KFtXXSldfXtsZXQgYz1fMHgzYWRkNWRbVygyOTEsMTk1LDE1OCwxNTAsImsoXkgiKV18fF8weDQ2NDhjYjtfMHgxZDk3ZGQ9ZltuKDQ5Nyw0NjIsImRpTSUiLDQzNiw2NDApXShfMHg1YTk5OWIsZlt0KDIyOCwiVmlybiIpXShfMHgxODY4NzcsW2NbZltuKDQ5MCw1MTEsImRpTSUiLDU5MCw1NzYpXShfMHgyNjkzNjVbNV0sOCldfHwiNCIsY1tmW24oNTQ2LDY3NiwiNEZlYyIsNDY0LDU3NSldKF8weDNmY2RjM1s4XSw4KV1dKSksXzB4NTBlYzhiW24oNjc4LDcxNiwiWk5jZyIsNzk4LDU1MSldKCl9fSxbSixqLEksVixaXT1bVz0+UFt0KDM1NywiOGNRZSIpXShXKSxXPT5QWyQoLTI4MiwtMjUzLC0yMzYsIlZpcm4iLC0yMDYpXShXKSwoKT0+UFt0KDM5NywiSyUqVyIpKyJtIl0oKSxXPT5XW3QoNDU4LCJLJSpXIildKDAsMTYpLCgpPT4wXSxbeSx2LE1dPVszLDB4NjQ0ZjYzNzAsZlt0KDIzNCwieXpCJCIpXSgyLGZbdCgyMDksIno0bDYiKV0oNCwzKSldLHc9KFcsbix0KT0+bj9XXnRbMF06VyxGPShXLG4sYyk9PntmdW5jdGlvbiByKFcsbixjLHIsbyl7cmV0dXJuIHQoYy0gLTEyNy0gLTQ4NixXKX1mdW5jdGlvbiBvKFcsbixjLHIsbyl7cmV0dXJuIHQoVy0gLTEzNzQtNDgzLG4pfWZ1bmN0aW9uIGUoVyxuLGMscixvKXtyZXR1cm4gdChuLSAtODI0LTM4MSxvKX1mdW5jdGlvbiB1KFcsbixjLHIsbyl7cmV0dXJuIHQoby0yODYtIC00ODYsYyl9aWYoZltyKCJnVnolIiwtMzk1LC0yNzgsLTE5NiwtMjgzKV0oZltvKC02OTEsIkJHSE0iLC03NjMsLTgwOCwtNjMwKV0sZltvKC01MDUsIikwKCMiLC01NzMsLTM3OCwtMzg0KV0pKXtpZighV1tlKDU0LC04OSwtMTA3LC05MCwiYXQyVCIpKyJ0ZSJdKXJldHVybjtsZXQgdD1XW3IoIjJwJU4iLC01MzgsLTQwNywtMjcwLC0zMTApKyJ0ZSJdKGZbdSgtNTEsMTUzLCIzRTZeIiwtMzAsNjIpXShELG4pLE0pO3RbZSgtMSwtMTExLDM0LC0yOCwiKTAoIyIpXSgpLHRbZSgtMTE1LC0xMzIsLTI2OCwtMjUwLCJ4ajRiIikrZSgtMTA4LC0yMzMsLTMyOCwtMzQxLCJGYSN2IikrImUiXT1mW2UoLTE3NCwtMTc5LC0xNjIsLTEwOSwiNEZlYyIpXShmW28oLTQ2OSwiZmszYyIsLTUwOCwtNTYzLC01NDUpXShKLGZbbygtNjQ5LCImTGohIiwtNTA5LC02MzQsLTc5NSldKGMsMTApKSwxMCl9ZWxzZXtsZXQgVz1fMHhjNmI3NmRbcigiZ1Z6JSIsLTI3OSwtMjIzLC0yNDYsLTExNCkrbygtNTQ4LCJadkhuIiwtNDY4LC02MjAsLTQ3MikrcigiJV4mcyIsLTI5NywtMTc0LC02MCwtMzkpXShmW3UoMTYxLDI3NywiYWEzIyIsMTIwLDE1MSldKTtyZXR1cm4gXzB4MWEyMDVjW3UoMjg2LDIxMywiUW13dCIsMzMyLDE4OSldW28oLTY0MywiYWEzIyIsLTc3MywtNjQ1LC02MDkpKyJkIl0oVyksW1csKCk9Pl8weDVjMzY5MyhbV10pXX19LFQ9KFcsbixjLHIpPT57ZnVuY3Rpb24gbyhXLG4sYyxyLG8pe3JldHVybiB0KG8tIC0xMjA5LTM4MSxXKX1mdW5jdGlvbiBlKFcsbixjLHIsbyl7cmV0dXJuIHQoVy00NDQtIC00ODYsYyl9ZnVuY3Rpb24gdShXLG4sYyxyLG8pe3JldHVybiB0KG8tIC02MTUtNDgzLHIpfWZ1bmN0aW9uIGQoVyxuLGMscixvKXtyZXR1cm4gdChyLSAtMjEtNDgzLGMpfWlmKGZbdSgyMDgsLTEsMTczLCJrKF5IIiwxMTQpXShmW2QoNTQzLDczOSwiejRsNiIsNjM1LDU5OSldLGZbdSgzMDUsMzQyLDI5NSwiIWpjUiIsMzA1KV0pKXtsZXQgdD1mW2QoODY1LDYzNiwiSyUqVyIsNzM2LDcwMCldKGZbbygiejRsNiIsLTYwMiwtNjY0LC02NjgsLTU3OSldKGZbZCg4NTQsOTQ5LCJadkhuIiw4NjQsOTUxKV0oVyxmW2UoMjA1LDEyOSwiNWg1SSIsOTUsMjQ3KV0oYyxuKSksMjU1KSxuKTtyZXR1cm4gcj9mW2UoMTU5LDI3LCImd05dIiwxODYsMTgwKV0oaix0KTp0W2QoOTkzLDc5MSwieVtoQiIsOTA3LDEwMzEpKyJlZCJdKDIpfXtsZXQgVz1mW2UoMjY1LDI2OSwiQkdITSIsMjU1LDMzMCldKGZbZCg5ODYsMTAxOCxpLDg4Miw3NDApXShmW28oIjRGZWMiLC01MDYsLTMxMSwtMjQ0LC0zNzcpXShfMHgxNzZmMGIsZltvKCIhamNSIiwtNTY3LC01OTYsLTQxOSwtNDU4KV0oXzB4MTkxZmE4LF8weDJmODhkNykpLDI1NSksXzB4MWFlMjNlKTtyZXR1cm4gXzB4MzdhZjMzP2ZbdSg2OSwyMzAsMTM4LCJ4ajRiIiwxNTcpXShfMHgyNWExZmMsVyk6V1t1KDI5MywzNzIsMjYwLGksMzI3KSsiZWQiXSgyKX19LEQ9Vz0+KHtjb2xvcjpbIiMiK3EoV1swXSkrcShXWzFdKStxKFdbMl0pLCIjIitxKFdbM10pK3EoV1s0XSkrcShXWzVdKV0sdHJhbnNmb3JtOlt0KDMyNiwiRlslSCIpK3QoMzI4LCJrKF5IIikrImcpIix0KDMyNiwiRlslSCIpKyJlKCIrVChXWzZdLDYwLDM2MCwhMCkrdCg0MTUsIlBUNmoiKV0sZWFzaW5nOnQoNDAxLCIqZ0RQIikrdCgyNDQsImF0MlQiKSt0KDIxOSwiJkxqISIpK0coV1tfKCJVKiRLIiw1NjUsNzEyLDYyMCw1ODMpXSg3KSlbdCg0MDgsIjJwJU4iKV0oKFcsbik9PlQoVyxuJTI/LTE6MCwxKSlbdCg0MzIsIiFqY1IiKV0oKSsiKSJ9KTtmdW5jdGlvbiBfKFcsbixjLHIsbyl7cmV0dXJuIHQoci0zODEsVyl9ZnVuY3Rpb24gVShXLG4sYyxyLG8pe3JldHVybiB0KHItIC03NTIsbil9bGV0IEUsWD1bXSxBLFk9Vz0+e2xldCBuPXtnSVdmQTpmdW5jdGlvbihXLG4pe3JldHVybiBmW3QoMjY3LCIycCVOIildKFcsbil9LERPdGJhOmZ1bmN0aW9uKFcsbil7cmV0dXJuIGZbdCg0MjMsIjdDUXoiKV0oVyxuKX0sV3dsd0M6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gZlt0KDM2MSwiQUhpTCIpXShXLG4pfSxOYVZPbzpmdW5jdGlvbihXKXtyZXR1cm4gZlt0KDE5OSwieXpCJCIpXShXKX0sZXJCT0Y6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gZlt0KDQxNiwiN3U1QiIpXShXLG4pfSxFQllpajpmW2MoNzczLDYzMiwiMnB0ciIsNjcyLDYzNyldLENqY2pUOmZbbygtMTQwLC02LC04NywxOCwiNyV2ISIpXSx3TE5yTTpmW2MoNzAyLDY2MSwiKjhFUyIsNjM1LDcxNSldLHRlRWRYOmZbbygxMDIsLTg5LDI5LC00MiwiM0U2XiIpXSxwcnVXSDpmdW5jdGlvbihXLG4pe3JldHVybiBmW3QoMTgyLCJ4MTlhIildKFcsbil9LHpMYVBSOmZ1bmN0aW9uKFcsbil7dmFyIGM7cmV0dXJuIGZbdCg0NDIsYz0iYWEzIyIpXShXLG4pfSxYV211SDpmdW5jdGlvbihXLG4pe3ZhciB0O3JldHVybiBmW3IoOTMsKHQ9ImFhMyMiKS0yMzAsNzQ1LHQsNTc2KV0oVyxuKX0sZmhFS0g6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gZltjKDE5MCxOYU4sIiZ3Tl0iLDI4Niw1OTkpXShXLG4pfSxCbFlOczpmdW5jdGlvbihXLG4pe3JldHVybiBmW3QoMzA0LCJhYTMjIildKFcsbil9LEV4TnNTOmZ1bmN0aW9uKFcsbil7cmV0dXJuIGZbdCgyOTUsIkJ4aW4iKV0oVyxuKX0sSWREc1g6ZltjKDYyMiw0NzksdSw2MzIsNDk3KV19O2Z1bmN0aW9uIGMoVyxuLGMscixvKXtyZXR1cm4gdChvLTEwNjktIC03NTIsYyl9ZnVuY3Rpb24gcihXLG4sYyxyLG8pe3JldHVybiB0KFctIC0zMjAtNDAscil9aWYoIUV8fGZbdCg0NDMsdSldKFcsQSkpe0E9VztsZXRbcixlXT1bZlt0KDIxNSxkKV0oV1szOF0sMTYpLGZbdCgxOTgsIlZpcm4iKV0oZltjKDcxNSw1MjgsImsoXkgiLDU3Nyw2MjcpXShmW3QoNDMwLGQpXShXWzIzXSwxNiksZlt0KDM4MiwiSyUqVyIpXShXWzEwXSwxNikpLGZbdCgyNTAsInlbaEIiKV0oV1syN10sMTYpKV0sdT1mW2MoODYyLDc4MSwiKjhFUyIsNzM4LDcyNCldKEssZlt0KDI5MSwiYyMySCIpXSxXKTtuZXcgYigoKT0+e2xldCByPSJGWyVIIjtmdW5jdGlvbiBvKFcsbixjLHIsbyl7cmV0dXJuIHQoci0xMTY0LSAtNDM1LTQwLG4pfWxldCBlPXtRUnFxcTpmdW5jdGlvbihXLGMpe3JldHVybiBuW3QoNDQxLCIhamNSIildKFcsYyl9LEJyVkdTOmZ1bmN0aW9uKFcsYyl7cmV0dXJuIG5bdCgyMTgsIikwKCMiKV0oVyxjKX0sTlpmVUg6ZnVuY3Rpb24oVyxjKXtyZXR1cm4gblt0KDI1OSwiN3U1QiIpXShXLGMpfX07ZnVuY3Rpb24gdShXLG4sYyxyLG8pe3JldHVybiB0KGMtNDA0LSAtNDM1LTQwLFcpfWZ1bmN0aW9uIGQoVyxuLHQscixvKXtyZXR1cm4gYyhXLTQwNCxuLTI1NyxXLHItNDIxLG8tMTcxKX1mdW5jdGlvbiBpKFcsbixjLHIsbyl7cmV0dXJuIHQoci0xMjY5LSAtNDM1LTQwLGMpfWZ1bmN0aW9uIGYoVyxuLGMscixvKXtyZXR1cm4gdChyLTY0MC0gLTQzNS00MCxuKX1pZihuW3UoIkJ4aW4iLDI5MiwyODEsMzgxLDMzMyldKG5bZig1OTksImsoXkgiLDY5Miw1ODMsNTgwKV0sbltmKDYzNiwiYyMySCIsNzcwLDY0OSw2MjEpXSkpe2xldCBjPW5ldyBILGE9bltvKDEzNDQsImMjMkgiLDEyMzEsMTIwNywxMjM5KV0oSSlbdSgieGo0YiIsMzUwLDQ0Myw1NzEsMzMxKStpKDEyMTksOTY4LCImTGohIiwxMDk4LDExNjEpXSgzNik7Y1tmKDQzNCwiWEBxSiIsMzczLDUxMyw2MjEpK2koMTI0NSwxMzcyLCJCR0hNIiwxMjQwLDExODQpK3UoIiZ3Tl0iLDI3OCwyOTIsMzMxLDI0NikrImVsIl0oYSksY1tmKDQ4MiwiVmlybiIsMzA4LDQxNCwzNjMpK3UoImFhMyMiLDI1NCwzNzMsNDgwLDMzMCkrInIiXSgpW3UoIno0bDYiLDg3LDE4MSwxNTgsMzAzKV0odT0+e2Z1bmN0aW9uIGkoVyxuLHQsYyxyKXtyZXR1cm4gZCh0LG4tMTk1LHQtMTAyLGMtMzU5LGMtIC0xOTIpfWZ1bmN0aW9uIGsoVyxuLHQsYyxyKXtyZXR1cm4gbyhXLTI1OSx0LHQtMTAsbi0xOTEsci04OCl9ZnVuY3Rpb24gUyhXLG4sdCxjLHIpe3JldHVybiBmKFctMzAxLHIsdC00MTYsbi02OTgsci01MDApfWxldCB4PXt1RnRxSDpmdW5jdGlvbihXLGMpe3JldHVybiBuW3QoMjExLCJGWyVIIildKFcsYyl9LGlTcG5COmZ1bmN0aW9uKFcsYyl7cmV0dXJuIG5bdCgzMDMsIkJHSE0iKV0oVyxjKX0sZ3NYQUQ6ZnVuY3Rpb24oVyxjKXtyZXR1cm4gblt0KDMzMCwieGo0YiIpXShXLGMpfSxQQXBteDpmdW5jdGlvbihXKXtyZXR1cm4gblt0KDI3MCwiWk5jZyIpXShXKX19O2Z1bmN0aW9uIG0oVyxuLHQsYyxyKXtyZXR1cm4gZihXLTI5OCxuLHQtMjQ4LHQtIC05MCxyLTE0Nyl9ZnVuY3Rpb24gQyhXLG4sdCxjLHIpe3JldHVybiBkKG4sbi0xNzgsdC0yMjMsYy0yNDIsci0gLTEyMTEpfWlmKG5bUygxMzI5LDEyNTYsMTE5MCwxMTg5LCIqZ0RQIildKG5bbSgzNDksIkJ4aW4iLDQwNiwzNDksNDA4KV0sblttKDQ1MiwiZmszYyIsNTg0LDUzNiw1NjcpXSkpdHJ5e2lmKG5bbSg0OTIsIlUqJEsiLDUzMCw1NzUsNTMzKV0obltrKDExMjUsMTI2NSwiYyMySCIsMTMzMSwxMzI2KV0sbltpKDUxNCw3MDUsIjcldiEiLDU4Niw2OTUpXSkpe2xldCB0PXVbUygxMjU2LDEzMzQsMTE5OCwxNDY2LCJmazNjIildfHxhO1g9bltrKDEyOTksMTIxNCwiYXQyVCIsMTI2NywxMjQxKV0oRyxuW20oNTk2LCJlKUB5Iiw1OTUsNTUwLDcwNCldKHAsW3RbbltrKDEzMjQsMTQwNCwieDE5YSIsMTMxNCwxNDE2KV0oV1s1XSw4KV18fCI0Iix0W25bQygtNDY0LCJRbXd0IiwtNTg4LC01NDUsLTQ4NSldKFdbOF0sOCldXSkpLGNbaSg2NDgsNjA1LCIyN2JlIiw2MzAsNjI1KV0oKX1lbHNle2lmKCFfMHgyMmRiNmNbaSg3NDcsNzcwLCJhdDJUIiw2NTAsNTE1KSsidGUiXSlyZXR1cm47bGV0IFc9XzB4YTgxMzI4W0MoLTM2NywieVtoQiIsLTMwNywtMzE0LC0zNzYpKyJ0ZSJdKGVbaSg2ODYsNjQzLCJ6NGw2Iiw3NTIsNjUwKV0oXzB4MjViN2RkLF8weDU5MjEwZCksXzB4NTI2MGE4KTtXW2koNjIxLDc0OCwiVSokSyIsNjUyLDcwNyldKCksV1tpKDc3MCw2NTQsImdWeiUiLDY2Nyw3NTkpK2koNTE1LDUzNCxyLDYyMyw1NDUpKyJlIl09ZVttKDM1NSwieGo0YiIsNDEyLDQzMSw0MjYpXShlW20oNTUyLCJVKiRLIiw0MDcsMzg0LDQ2MyldKF8weDNiMjcwZixlW1MoMTQ1NiwxMzQzLDEzMTksMTQ4MCwiUW13dCIpXShfMHgyYmJiOTQsMTApKSwxMCl9fWNhdGNoe31lbHNle2xldCBXPW5ldyBfMHgxN2Q1YWYsbj14W2koNzU5LDg4NCwiSyUqVyIsNzUwLDc3NSldKF8weDJkMTFiMClbaSg2MDYsNTI5LCJLJSpXIiw1NjcsNzEzKSttKDQzNCwiVSokSyIsMzg0LDM2NCwzMTQpXSgzNik7XzB4NTZiODEyPVdbUygxMzk1LDEzMzEsMTQ2NiwxNDEwLCJdKV5WIikrbSgxOTAsImMjMkgiLDMzMSwyNDAsMzAxKStrKDEzMjksMTM3MywiZmszYyIsMTQ0OSwxMjg2KSsiZWwiXShuKSxXW1MoMTA4MiwxMTU1LDExNzAsMTAzMiwiN0NReiIpK2soMTE1NCwxMjkzLHIsMTI4NSwxMzM0KSsiciJdKClbaSg1NDgsNTk3LCI3JXYhIiw2NzksNTMzKV0odD0+e2Z1bmN0aW9uIGMoVyxuLHQsYyxyKXtyZXR1cm4gQyhXLTQ4LG4sdC02MCxjLTQ1LHQtOTY0KX1mdW5jdGlvbiByKFcsbix0LGMscil7cmV0dXJuIFMoVy00OTgsVy0gLTUyMix0LTM5OCxjLTE3NixuKX10cnl7dmFyIG87bGV0IGU9dFtyKDgyMCwiN0NReiIsNzI0LDY4Nyw5MDkpXXx8bjtfMHgzNmRhMjA9eFtyKDc5OCwiSlV1SiIsNzU3LDY4Nyw3OTQpXShfMHgxYzc2NjQseFtpKC0zMTQsODgsIjVoNUkiLDU5OCwtMjc1KV0oXzB4MTNkOThhLFtlW3hbbz0iNyV2ISIsaygtNzMxLDEyNDEsbywtNjc4LG8tMzMzKV0oXzB4NmNkM2ZkWzVdLDgpXXx8IjQiLGVbeFtjKDUzNSwiWEBxSiIsNTUwLDQxMiw0NTApXShfMHg0MmEyNDdbOF0sOCldXSkpLFdbYyg1MjIsImMjMkgiLDYxNSw3NTcsNjU2KV0oKX1jYXRjaHt9fSlbaygxMzA3LDEyMzUsIiZ3Tl0iLDEzNTIsMTI1MCldKF8weDdiNzM1MCl9fSlbdSgiJkxqISIsMjYxLDE4MCwxNDgsMTEzKV0oWil9ZWxzZSB0cnl7bGV0IFc9XzB4NTViMTQwW2YoNjc0LCJDT3pbIiw3MzEsNjczLDYwNyldfHxfMHg1YjFiMzU7XzB4MWQyOTZmPW5bbyg5NDAsIlUqJEsiLDg4Nyw5NTIsMTAwMSldKF8weDMxNzgwMyxuW28oODgxLCJCeGluIiwxMDE3LDEwMjUsODk3KV0oXzB4NGRjMTIwLFtXW25bZCgiYWEzIyIsNzE3LDgxMiw2NzAsNjgwKV0oXzB4M2FjZDk2WzVdLDgpXXx8IjQiLFdbbltmKDQ4NCwiXSleViIsNTE3LDYxNCw0OTApXShfMHg1ZjE2YThbOF0sOCldXSkpLF8weDE5MDA5M1tpKDExODAsMTE1NiwiSlV1SiIsMTE4NiwxMjY1KV0oKX1jYXRjaHt9fSlbdCgzMzksZCldKFopO2xldFtpLGFdPWZbdCgyMzcsIjhjUWUiKV0oZyk7ZltjKDQ1MSw2MTYsIio4RVMiLDUzNiw1MTApXShGLGksdVtyXSxlKTtsZXQgaz1mW2MoMzY1LDQxNSwiKjhFUyIsNDA2LDUwMSldKGgsaSk7RT1mW28oLTEzNiwtMjgyLC0xNjQsLTcxLCJCR0hNIildKEcsKCIiK2tbdCgzNjAsIjcldiEiKV0ra1t0KDQ0NywiVSokSyIpK2MoNjY3LDYyOSwieGo0YiIsNTczLDU0MyldKVt0KDI3NiwiZ1Z6JSIpK3QoMjYxLCJKVXVKIildKC8oW1xkLi1dKykvZykpW3QoMjM2LCIlXiZzIildKFc9PlMoUyhXWzBdKVtmdW5jdGlvbihXLG4sYyxyLG8pe3JldHVybiB0KGMtMzcyLSAtNzUyLG8pfSg3NSwxNTIsNTUsMTAwLCIycCVOIikrImVkIl0oMikpW3QoNDIxLCI3dTVCIikrZnVuY3Rpb24oVyxuLGMscixvKXtyZXR1cm4gdChjLTM3Mi0gLTc1MixvKX0oMzEsMTk4LDczLDE3NSwiZGlNJSIpXSgxNikpW3QoMzg0LCJBSGlMIildKCIiKVtjKDY1Miw2NDksIjRGZWMiLDY3MCw1MzkpKyJjZSJdKC9bLi1dL2csIiIpLGZbbygtMTY0LC0yNDIsLTE0OSwtMjA4LCJDT3pbIildKGEpfWZ1bmN0aW9uIG8oVyxuLGMscixvKXtyZXR1cm4gdChjLTM3Mi0gLTc1MixvKX1yZXR1cm4gRX07ZnVuY3Rpb24gJChXLG4sYyxyLG8pe3JldHVybiB0KG8tIC00ODYscil9cmV0dXJuIGFzeW5jKFcsbik9PntmdW5jdGlvbiBjKFcsbixjLHIsbyl7cmV0dXJuIHQoVy0yMjEtNDAsYyl9ZnVuY3Rpb24gcihXLG4sYyxyLG8pe3JldHVybiB0KGMtIC02MTUtMzgxLFcpfWZ1bmN0aW9uIHUoVyxuLGMscixvKXtyZXR1cm4gdChvLSAtMTAxMC00ODMsYyl9ZnVuY3Rpb24gZChXLG4sYyxyLG8pe3JldHVybiB0KGMtIC0xMzYxLTM4MSxuKX1sZXQgaT1mW3IobywtNywxMzMsNjIsMjEpXShqLGZbZCgtNTA1LGUsLTU2MSwtNTU4LC02NjgpXShmW2MoNjczLDczOSwiZGlNJSIsNzE3LDc1MSldKFJbZCgtNzQ1LCIpMCgjIiwtNjY1LC03NjksLTYxNildKCksZltkKC01NDksInlbaEIiLC02NjIsLTczNCwtNjIwKV0odiwxZTMpKSwxZTMpKSxhPW5ldyBtKG5ldyBsKFtpXSlbcigiQ096WyIsLTE5NiwtNTUsNjMsNykrInIiXSksaz1BfHxmW3IoIlpOY2ciLDUzLDEzMSwyMjIsMjUwKV0ocyksUz1mW2MoNDc3LDQzOCwiQkdITSIsNTc1LDUyMyldKFksayk7cmV0dXJuIGZbdSgtMTQ2LC0yNTksIngxOWEiLC0zMTUsLTI0MildKFEsbmV3IG0oW2ZbdCgxNzUsIlFtd3QiKV0oZltkKC02ODEsIlUqJEsiLC02MjIsLTYxNiwtNzE2KV0oSSksMjU2KV1bdSgtMjgxLC0zNjksIlpOY2ciLC0yNjEsLTMxNCkrInQiXShmW2MoNTE0LDU0OCwiQUhpTCIsNjU4LDYwNSldKEcsayksZlt0KDIyMCwiKTAoIyIpXShHLGEpLGZbdSgtMzE3LC00MjgsIjVoNUkiLC0yNzEsLTI5NyldKFYsZltyKGUsNjUsNDUsMywtMTUpXShHLG5ldyBtKGF3YWl0IGZbdSgtMzI4LC0yNzYsInlbaEIiLC0zNDMsLTMxOSldKE4sZltjKDUxNiw1OTQsIjVoNUkiLDQ3NiwzOTYpXShmW3UoLTI1MSwtOTMsIno0bDYiLC0yMjYsLTE5NildKFtuLFcsaV1bdCgyOTgsIjJwdHIiKV0oIiEiKSxmW3UoLTM0MiwtMjkzLCJ5ekIkIiwtMzI2LC0yOTQpXSksUykpKSlbYyg1MDEsNTY3LCIlXiZzIiw0NjcsNjQ0KSsidCJdKFgpKSxbeV0pKVtyKG8sMTY4LDE5OSwzMDEsMjE3KV0odykpfX1dKX1dKTsKCi8vIyBkZWJ1Z0lkPWU4YzE0MGNiLTQ5MzUtZjNjOS1kMTI2LTg3ODE0NmJjZDMxNAovLyMgc291cmNlTWFwcGluZ1VSTD0wZmRzNmM5LWV0LTQxLmpzLm1hcA==";

// 加载 grok 原版签名 chunk,捕获 default 导出(async signer)。
// 默认用本文件内嵌的 SIG_CHUNK_B64(单文件自包含);设 STATSIG_CHUNK=路径 可覆盖为外部文件。
function loadRawSigner() {
  let signer = null;
  globalThis.TURBOPACK = {
    push(entry) {
      entry[2]({ s(arr) { if (Array.isArray(arr) && arr[0] === "default" && typeof arr[2] === "function") signer = arr[2](); } });
    },
  };
  const code = process.env.STATSIG_CHUNK
    ? fs.readFileSync(process.env.STATSIG_CHUNK, "utf8")
    : Buffer.from(SIG_CHUNK_B64, "base64").toString("utf8");
  (0, eval)(code);
  if (typeof signer !== "function") throw new Error("未能捕获 default signer 导出");
  return signer;
}

// ===========================================================================
// 公开 API
// ===========================================================================
let _rawSigner = null;

/**
 * 创建签名器(加载一次 chunk,可复用)。
 * @returns {Promise<(pathname:string, method:string, q:string)=>Promise<string>>}
 */
async function createSigner() {
  installEnv();
  if (!_rawSigner) _rawSigner = loadRawSigner();
  return async (pathname, method, q) => {
    if (!q) throw new Error("缺少 Q(从 grok 首页 meta 取,见 fetchQ)");
    CURRENT_Q = q;
    return _rawSigner(pathname, method); // 注意:grok 签名器入参顺序 (pathname, method)
  };
}

/**
 * 从 grok 首页 HTML 取一次 Q(meta 站点校验串,base64)。
 * ⚠️ 需带 cookie(至少 cf_clearance),否则被 Cloudflare 挑战页(403)拦截、无 Q。
 *    生产中通常已有账号 cookie;或直接把已知 Q 传给 signer,无需本函数。
 * @param {{proxy?:string, cookie?:string}} opts
 * @returns {Promise<string>}
 */
async function fetchQ(opts = {}) {
  const proxy = opts.proxy !== undefined ? opts.proxy : DEFAULT_PROXY;
  const cookie = opts.cookie || process.env.GROK_COOKIE || "";
  let html;
  if (proxy) {
    html = await httpsGetViaProxy("https://grok.com/", proxy, cookie);
  } else {
    const h = { "user-agent": UA, "accept": "text/html" };
    if (cookie) h.cookie = cookie;
    html = await (await fetch("https://grok.com/", { headers: h })).text();
  }
  if (/just a moment|challenge-platform/i.test(html))
    throw new Error("被 Cloudflare 拦截(无有效 cf_clearance)。请通过 cookie 选项/GROK_COOKIE 传入账号 cookie。");
  for (const m of html.matchAll(/content="([^"]+)"/gi)) {
    const c = m[1];
    try { if (Buffer.from(c, "base64").length === 48) return c; } catch (_) {}
  }
  throw new Error("未在首页 HTML 找到 Q(48字节 meta)");
}

// 零依赖 https GET(经 http 代理 CONNECT 隧道);请求 identity 编码免解压,自动去 chunked。
function httpsGetViaProxy(targetUrl, proxy, cookie) {
  return new Promise((resolve, reject) => {
    const net = require("net"), tls = require("tls");
    const t = new URL(targetUrl), p = new URL(proxy);
    const sock = net.connect(+p.port, p.hostname);
    sock.setTimeout(30000, () => sock.destroy(new Error("proxy timeout")));
    sock.on("error", reject);
    let hdr = Buffer.alloc(0), connected = false;
    sock.once("connect", () => sock.write(`CONNECT ${t.hostname}:443 HTTP/1.1\r\nHost: ${t.hostname}:443\r\n\r\n`));
    sock.on("data", function onData(buf) {
      if (connected) return;
      hdr = Buffer.concat([hdr, buf]);
      const idx = hdr.indexOf("\r\n\r\n"); if (idx < 0) return;
      if (!/ 200 /.test(hdr.slice(0, hdr.indexOf("\r\n")).toString())) return reject(new Error("代理 CONNECT 失败: " + hdr.toString().split("\r\n")[0]));
      connected = true; sock.removeListener("data", onData);
      const req = `GET ${t.pathname || "/"} HTTP/1.1\r\nHost: ${t.hostname}\r\nUser-Agent: ${UA}\r\n` +
                  `Accept: text/html\r\nAccept-Encoding: identity\r\n` + (cookie ? `Cookie: ${cookie}\r\n` : "") + `Connection: close\r\n\r\n`;
      const s = tls.connect({ socket: sock, servername: t.hostname }, () => s.write(req));
      let resp = Buffer.alloc(0);
      s.on("data", (c) => (resp = Buffer.concat([resp, c])));
      s.on("error", reject);
      s.on("end", () => {
        const hi = resp.indexOf("\r\n\r\n");
        const headers = resp.slice(0, hi).toString();
        let body = resp.slice(hi + 4);
        if (/transfer-encoding:\s*chunked/i.test(headers)) {
          let out = Buffer.alloc(0), i = 0;
          while (i < body.length) {
            const j = body.indexOf("\r\n", i); if (j < 0) break;
            const size = parseInt(body.slice(i, j).toString(), 16); if (!size) break;
            out = Buffer.concat([out, body.slice(j + 2, j + 2 + size)]); i = j + 2 + size + 2;
          }
          body = out;
        }
        resolve(body.toString("utf8"));
      });
    });
  });
}

module.exports = { createSigner, fetchQ, M_PATHS };

// ===========================================================================
// 常驻 worker 模式(--serve):供宿主进程(本项目 Python)按行调用
// ---------------------------------------------------------------------------
// 协议:stdin 每行一个请求 JSON  {"id":N,"pathname":"/rest/…","method":"POST"[,"q":"…"]}
//       stdout 每行一个响应 JSON {"id":N,"sig":"…"}  或  {"id":N,"err":"…"}
// Q 由 worker 自取(fetchQ:代理读 HTTPS_PROXY/ALL_PROXY,cookie 读 GROK_COOKIE)
// 并按 TTL 缓存;fetchQ 失败时沿用上次成功的 Q,避免抖动。
// ===========================================================================
const Q_TTL_MS = 30 * 60 * 1000;

async function runServe() {
  const sign = await createSigner();
  let cachedQ = null;
  let cachedAt = 0;

  const ensureQ = async (forced) => {
    if (forced) return forced;
    const fresh = cachedQ && Date.now() - cachedAt < Q_TTL_MS;
    if (fresh) return cachedQ;
    try {
      cachedQ = await fetchQ();
      cachedAt = Date.now();
    } catch (e) {
      if (cachedQ) {
        process.stderr.write("[x-statsig-id] fetchQ 失败,沿用旧 Q: " + (e && e.message || e) + "\n");
        return cachedQ;
      }
      throw e;
    }
    return cachedQ;
  };

  // 串行化:逐行排队处理,避免并发 fetchQ 竞争。
  let chain = Promise.resolve();
  const write = (obj) => process.stdout.write(JSON.stringify(obj) + "\n");

  const rl = require("readline").createInterface({ input: process.stdin });
  rl.on("line", (line) => {
    const text = line.trim();
    if (!text) return;
    chain = chain.then(async () => {
      let req;
      try {
        req = JSON.parse(text);
      } catch (e) {
        return write({ id: null, err: "bad json: " + (e && e.message || e) });
      }
      try {
        const q = await ensureQ(req.q);
        const sig = await sign(req.pathname || "/rest/app-chat/conversations/new", req.method || "POST", q);
        write({ id: req.id, sig });
      } catch (e) {
        write({ id: req.id, err: (e && e.message || String(e)) });
      }
    });
  });
  rl.on("close", () => { chain.then(() => process.exit(0)); });
  process.stderr.write("[x-statsig-id] serve 就绪\n");
}

// ===========================================================================
// CLI
// ===========================================================================
if (require.main === module) {
  if (process.argv[2] === "--serve") {
    runServe().catch((e) => { process.stderr.write("[error] " + (e && e.stack || e) + "\n"); process.exit(1); });
  } else {
    (async () => {
      const pathname = process.argv[2] || "/rest/app-chat/conversations/new";
      const method = process.argv[3] || "POST";
      let q = process.argv[4];
      if (q === "-" || q === undefined) {
        process.stderr.write(`[x-statsig-id] 抓取 Q (proxy=${DEFAULT_PROXY || "direct"}) ...\n`);
        q = await fetchQ();
      }
      const sign = await createSigner();
      const sig = await sign(pathname, method, q);
      process.stdout.write(sig + "\n");
      process.stderr.write(`[x-statsig-id] ${method} ${pathname}  len=${sig.length}  Q=${q.slice(0, 12)}…\n`);
    })().catch((e) => { process.stderr.write("[error] " + (e && e.stack || e) + "\n"); process.exit(1); });
  }
}
