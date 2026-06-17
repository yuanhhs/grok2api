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
  "M 10,30 C 130,49 153,8 71,88 h 216 s 120,202 220,7 C 207,57 22,199 78,154 h 242 s 46,212 23,55 C 108,209 152,22 125,102 h 12 s 36,108 252,32 C 189,143 76,111 190,244 h 21 s 163,155 106,239 C 157,218 149,117 248,198 h 116 s 22,158 93,52 C 27,116 189,115 138,213 h 131 s 140,58 219,203 C 21,193 147,167 62,232 h 174 s 66,173 238,235 C 37,26 110,12 206,57 h 119 s 74,174 116,207 C 10,159 72,229 172,56 h 93 s 197,30 97,128 C 20,119 18,154 148,68 h 212 s 22,29 235,217 C 129,237 70,201 153,13 h 123 s 0,194 235,100 C 129,116 121,209 126,82 h 165 s 69,161 54,107 C 207,198 16,146 54,214 h 61 s 107,218 8,53 C 15,9 189,192 163,14 h 34 s 120,176 7,17 C 49,10 177,120 149,184 h 183 s 67,153 129,254 C 37,152 214,24 147,248 h 171 s 89,155 165,210",
  "M 10,30 C 31,20 106,98 147,172 h 167 s 49,47 212,250 C 61,109 96,134 244,83 h 180 s 72,1 114,111 C 227,91 108,168 180,228 h 10 s 69,164 200,152 C 20,73 136,192 124,247 h 107 s 92,9 45,138 C 10,44 215,64 57,81 h 251 s 66,189 81,45 C 32,64 246,120 120,13 h 100 s 70,209 35,232 C 134,140 50,180 178,7 h 48 s 17,206 7,232 C 214,85 152,97 118,62 h 153 s 1,151 185,31 C 93,191 19,8 30,63 h 237 s 72,134 224,126 C 99,194 168,45 214,71 h 120 s 85,104 26,187 C 0,209 242,99 218,27 h 210 s 158,240 56,55 C 106,153 56,182 214,68 h 117 s 247,185 48,97 C 99,163 1,174 66,252 h 95 s 68,254 5,214 C 117,6 70,223 49,42 h 208 s 141,60 131,135 C 109,232 76,121 165,102 h 254 s 239,35 99,201 C 81,212 135,38 242,23 h 129 s 103,99 227,208",
  "M 10,30 C 173,245 149,62 91,51 h 150 s 164,83 170,230 C 82,13 146,52 88,153 h 103 s 39,120 207,138 C 1,75 61,165 141,223 h 166 s 7,197 26,186 C 252,19 33,175 104,42 h 152 s 113,68 12,199 C 10,82 228,73 205,66 h 155 s 174,44 119,27 C 65,118 62,150 11,82 h 140 s 214,204 131,49 C 224,46 183,58 187,227 h 22 s 175,183 219,135 C 8,44 227,183 51,42 h 217 s 125,177 128,85 C 63,248 160,107 155,210 h 89 s 53,202 234,216 C 147,20 221,167 69,153 h 143 s 187,198 39,170 C 25,189 69,37 152,108 h 58 s 234,23 157,180 C 115,85 158,10 118,89 h 90 s 29,192 242,7 C 47,69 107,155 13,163 h 211 s 237,25 12,198 C 101,131 38,166 153,249 h 19 s 19,205 17,12 C 251,201 125,153 74,150 h 40 s 141,109 235,21 C 144,16 248,254 15,253 h 96 s 14,65 45,140",
  "M 10,30 C 55,117 186,250 21,177 h 87 s 78,126 226,55 C 71,243 86,60 23,94 h 1 s 122,64 102,78 C 140,252 228,167 62,46 h 0 s 51,210 222,91 C 212,177 15,43 253,174 h 9 s 175,164 120,134 C 194,3 66,24 104,29 h 213 s 151,191 88,142 C 186,247 41,105 93,46 h 52 s 190,45 219,246 C 101,96 74,129 63,138 h 105 s 179,71 239,157 C 133,108 64,38 86,13 h 251 s 17,146 94,38 C 205,165 107,232 186,103 h 115 s 130,66 237,62 C 193,161 194,215 111,16 h 56 s 37,70 25,218 C 199,4 240,39 51,141 h 152 s 114,140 244,100 C 105,24 146,73 36,44 h 193 s 238,68 121,176 C 217,85 70,107 123,88 h 1 s 173,87 201,93 C 133,95 249,132 8,125 h 217 s 239,250 113,164 C 150,232 158,240 53,180 h 194 s 241,38 30,73 C 13,174 101,183 177,133 h 221 s 201,182 29,240",
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
const SIG_CHUNK_B64 = "OyFmdW5jdGlvbigpe3RyeSB7IHZhciBlPSJ1bmRlZmluZWQiIT10eXBlb2YgZ2xvYmFsVGhpcz9nbG9iYWxUaGlzOiJ1bmRlZmluZWQiIT10eXBlb2YgZ2xvYmFsP2dsb2JhbDoidW5kZWZpbmVkIiE9dHlwZW9mIHdpbmRvdz93aW5kb3c6InVuZGVmaW5lZCIhPXR5cGVvZiBzZWxmP3NlbGY6e30sbj0obmV3IGUuRXJyb3IpLnN0YWNrO24mJigoZS5fZGVidWdJZHN8fCAoZS5fZGVidWdJZHM9e30pKVtuXT0iMjllNTc1OGEtM2ZlZS1lNDMzLTQyMDktYmNkOGNiNzk2MzRiIil9Y2F0Y2goZSl7fX0oKTsKKGdsb2JhbFRoaXMuVFVSQk9QQUNLfHwoZ2xvYmFsVGhpcy5UVVJCT1BBQ0s9W10pKS5wdXNoKFsib2JqZWN0Ij09dHlwZW9mIGRvY3VtZW50P2RvY3VtZW50LmN1cnJlbnRTY3JpcHQ6dm9pZCAwLDE2NDVlMyxuPT57InVzZSBzdHJpY3QiO2Z1bmN0aW9uIFcoKXtsZXQgbj1bIkFlYkZoOG9yIiwiZjhrd2FTb1NXUmUiLCJ0clNDVzROY1FHIiwiV1BOY1E4b2FXUHFuIiwiV1FCY1VTa0tsTFMiLCJxbWs5YkdTNCIsIldPYXJDMEpkTmEiLCJXN1RJV1FGZExIOCIsIm4xTDFXNWRkVmEiLCJobWtZY1NvU1dQVyIsIldPSmNWOGtpV1FoZE5HIiwiV1FYVFc2ZXVXUHkiLCJsd1NFeDhvViIsIldPalBicXJCIiwiVzdkZE5XN2NSOGtIIiwiV1JKZE1TbzNzZEMiLCJXUkNWVzRyOWthIiwiVzZqaEJTa2VCRyIsImtodnlXN3pYIiwiVzZUWERjZGNTRyIsIldQaGRPU2twaEs0IiwiVzZ1aVdSSFBpVyIsIlc3WmRVdVciLCJXTzFBbjhrR1c1ZSIsIlc3bGRRTEwzV1FxIiwiV1BMMGdxcnkiLCJBbWswemEiLCJBeEJjTG1rcWpXIiwiVzRTZ2lTbzR3RyIsInRta0R4U2tvVzZhIiwiVzZhb2NTb0xFcSIsIlc3OXZxU2s3V1BHIiwibFNrM2E4b2NXUnkiLCJXNVJjUDI4OXRHIiwiVzR1cFdSTE5mYSIsInZ1bGNIbWs1V1BlIiwiVzY1RHVDa3d6cSIsImkzRFBXN1hnIiwiV1BsY1NtazNXUXhkU1ciLCJEZm1RVzRhYiIsIlc0VmRTc1JjVlNrQSIsIldSL2RUOG8zeVp5IiwicVNrNno4a1MiLCJXUjNkUThvT0R0MCIsIlc0YXZXUkQ0ZmEiLCJtbWtqanJCZE9XIiwiV1BkZFVTb21XUjRJbzhvSEFJcGRTSnJzIiwiaDAxNlc2aGRUVyIsInRzMDVXNkJjVWEiLCJ2dnZzbG1vdiIsIldQaGNPQ2tiZ2ZTIiwiaW1reFdRZGRKWnEiLCJXNHhkUW1rUWVtb08iLCJXN1hqdWhWZElhIiwidXFhMlc3L2NMcSIsIldPeGNTbWtpV1JCZE5HIiwiVzROZFBHTyIsIm04b2FXT05jU0hHZWQ4a0Z0Y05jSWNTIiwieUNrRWp0U0oiLCJyOGtEejhrUVc2VyIsImQ4b05XUU5jS1NvNCIsIldScnV2Q29PVzdDaHF2dGNSSnBkSWJaZE1LaSIsInI4a2FreFRPIiwiV1BIUmFhbmkiLCJyOGtNalh5SyIsIldRWGtXT1RCVzZCY01ZOEpXUkpkUXEiLCJDR0NMVzUvY0lXIiwiYThrSldQM2RRc20iLCJXN3hjVTJXIiwiZW1vZUVZcTFXNlZjSUNrQ1c2TmNLQ29qa1ciLCJxM3VWVzdXRSIsIm1Tb2pXUEpkUm1rTyIsIlc0WGp1ZEpjTGEiLCJXUWxjSWVaY1JTazUiLCJXT2RjT1NvRFdQYUkiLCJnQ2tvaUpKZFZxIiwibENrNVc3VDR0VyIsImhZcjVXUXpmYThvb1dPRmRKQ2t6aEpQTiIsIlc2M2NROGtRa2dsZFRmekxsYUc4Vzc3ZE5XIiwiY21rQlc0WFZGRyIsIlc1eGRTSC9jUkNrbiIsImM4a1ZXUVJkS0dxIiwidG1rMWlyeWUiLCJXN3RkTHNaY1Nta0siLCJXNDBUbDhvSnNxIiwidlNrMGJaYUoiLCJXNFdta0NrKyIsIlc3NFJXNGU5Vzc4IiwiRmcvZExoOEkiLCJXNjdjTXdpN3JhIiwiVzRQenY4a3pXT2UiLCJXNmRjVUxwY0txaSIsInAxem1XNVAxIiwiVzZMQXhTa1oiLCJXNVBGeGEiLCJXNzh2V09HIiwiV09sY09kWFBXT3UiLCJDZ0hpdXZ1IiwiclNrdW8zNUwiLCJXN1JkTTJYRVdPbSIsIkFocGNJRyIsIldPSmRSbW9QQ0lDIiwiZ0NvRGtyUmRKcSIsIlc0U0NsbW8rc1ciLCJXNlBwcnEiLCJXUGxjTzhvYVdSV2giLCJyZnhjS0NrMFdPcSIsIldSWmRWOGtYbWEiLCJXUEJjT21va1dPMGYiLCJuQ2tvV1EzZEtaaSIsInI4azJqcSIsIldRcGRWd3pYV1JXIiwibGZQRVc1dSIsImdDa2VXNnpqeUciLCJiU282V1F4Y05xIiwiVzR5K1dSNUpvVyIsImtTa2NXNmoweHEiLCJqMVRFVzVCZFVxIiwibVNrdVdPTmRJdDQiLCJXUENNVzc1Q2NHIiwicG1vM1dPL2NMOG9mIiwiVzdDQlc0RyIsIldQM2NHbWthIiwidThrNlc0L2RJZXUiLCJXUE5jSjhreCIsIlc0V3BnYSIsIlc2SEZ3Q2szV1E4IiwiVzdOZE5Da2twU28wIiwiV1B4Y0dta29lMTgiLCJXNGRkVG1reGs4b1IiLCJuOG9Va1NvOVdRTmRJOG9WQW1vUm44a21nbWt0VzdhIiwiZzhrZWFTb2hXUGEiLCJXNDBZVzQ4Vlc1RyIsInZmNUJyZTAiLCJiZnJVVzZOZFRxIiwiV1I1bVc2ODZXUEciLCJuQ295V1BSZEw4ay8iLCJXUHlsVzZMdGZxIiwiVzZIMldPQmRVYWEiLCJpTFhxVzU3ZFFXIiwiVzVpb1dSSGZqRyIsIldQRmNHQ2tqaHY4IiwiVzRkZFFDa0xtQ29RIiwiZkNveVdPZGRPbWtsIiwiaUxmRlc3cXIiLCJkbWtSYVhoZFVXIiwiVzZuOVdPaU1DbW9UVzRyQldPTHBXNnpUIiwiVzVaZFV1THhXUFciLCJ0TkhoYnEiLCJXNVJkVVNrVGJDbzgiLCJ2MHRkVFciLCJBTkR1Iiwib05Qa1c0bkMiLCJXUlpjSk1KY01Ta0UiLCJXNFNCazhvMnhhIiwiYThrOVc1TDR3YSIsImFHTmRLOGtBV08wZFc1M2NPZHkiLCJydmZqbjhvUyIsIlc1U25wRyIsInI4a0FrMnEiLCJwbWtQVzRQOUZXIiwicTJiaXpneSIsIlc0aGRVTjlZV1BLIiwiV1FWY0lNTmNRU2t1IiwiVzdxc2FTa3RXUnkiLCJ5Z1R3ZG1vWiIsIldRM2NSbW9oV08xRiIsImRTb21ocnRkVXEiLCJEQ2t4ZGhMZSIsIldQVmRTZm56V08wIiwiV1JaZEtTa1BodUMiLCJiaGJVVzdCZEpxIiwiaUNvR2E4bzlXUWEiLCJXUkNJVzU5VGpxIiwidHhKZFRlT3UiLCJqQ29BV1FoZE84a1YiLCJ2MWxkUTI0IiwiV1J1K1c0YjdsRyIsIm5Ta2FtV2EiLCJ2bW9OV1AvZEpDa2RXNER6IiwiVzZhS2FtazVXUU8iLCJXNXllbFNrbldQdSIsIlc1bGRRQ2tSbUciLCJXUFZjVWRIViIsIldQSmNQU2tmV1FCZExXIiwiaW1rQmZ0RmRPVyIsImlDazhXUEJkVFdtIiwiQ21rbFc1bGRPdnUiLCJXUnVsVzVETWtHIiwiaTFUZCIsIldPZnNlbWs5VzYwIiwiRk5OY01Da0JsYSIsImFtb1J6WjBJV1FaZEowL2NJcSIsImdtbzlXUU5jTnEiLCJsU29CV08zZEs4a1IiLCJXNmIzem1rWUJxIiwiVzYwc1dSalZqYSIsIldSbGNMOGtLV1J4ZFFxIiwiRXg0Tlc2ZmoiLCJEbWsrRlNrTVc2OCIsIldRcVZXNHZUanEiLCJXN1g4Q0NranVxIiwidmZwZFBxIiwidHUvZFJ4cXAiLCJXNnRjUWdaY1RXUyIsInhkYngiLCJXN3VhaFNrNVdRSyIsIlc0dGROU2tZZkNvVCIsIldRdGNKbWtLZ05DIiwiczN4Y1VDa3FhcSIsIkVOTmNLOGt6a3EiLCJBSE9wVzZCY0hHIiwiVzZ5dWhTa1VXUWkiLCJXT3o2aGEiLCJXNUNwV1I5TiIsInVDa3hxQ2tIVzZLIiwidG1rQWlxIiwia0NvVFdPRmRKbWtEIiwidDhrdGpMSE0iLCJoU2tVVzdMMXZXIiwiVzRwZE9HN2NOU2thIiwiVzc1YkM4azdXUXEiLCJXNk9qYXRsY05XIiwiaWY5elc2eWEiLCJpWFdBZjBmbldQMXhqbW9pIiwiV09KZFZTb0d6YnkiLCJhS2pjVzZPRCIsIldST2NkbW9EbWFaY0gxRFB4dkZkSVciLCJXNGRjTU54Y01yOCIsIlc0UmRQSHBjSENrciIsIldPTFFXN0NqV1BDIiwicUNrT2ZKMDciLCJXT1pjU1pmNldQSyIsIlc0YUpXNWVrVzVlIiwiVzZ2cXRta01CVyIsImwyalZXN0QxIiwiVzQ3Y1JDa3oiLCJ0TkpjVkNrOGNHIiwiVzc3ZFJNWDNXUjQiLCJXNTlwVzRLSVdPSmROTUciLCJXUi9jR01PIiwiYUtqZVc2bGRNcSIsIlc2NWR3OGtlRGEiLCJXNkdhaGEiLCJ0Q2thVzZKZFUzQyIsIlc0aWdqOG81IiwibThvd1dPZGRQbWtPIiwiVzZKY1VMR013YSIsIlc3blhyQ2tLV1F5Iiwid0ltdFc2bSIsImp2MUVXNUZkVmEiLCJBQ2swdDJSY0tmUmRSQ296ZndCY1V0SyIsIm1Db0tjVyIsInJTa0RqTmZQIiwiV1JxenMyQmRMRyIsInRLM2RSTUt1IiwiV1F4Y0hXdm5XUHEiLCJXNHZ3RVNreHVxIiwiV1EwZ0VoVmRJVyIsInVTa2R6OGs1VzRXIiwiZVNrbldPTmRVSUciLCJBTVZkSjBPMyIsInlTa3dXNE5kUkciLCJXUWJ0dzhrRkFxIiwiV1BMK2hhekQiLCJXNTRwZENrWFdRaSIsIlc0T3BobW95cXEiLCJXNlR1V1JwZE5YNCIsIlc1U2ZqOG8wdHEiLCJrbWs4ZG1vQ1dQVyIsInZJeUFXNDdjVGEiLCJ5aGZGVzd1diIsInIwN2RWMk9mIiwidG1rVmF2NWIiLCJ0cUN0VzZSY1JxIiwiYkNvSXowRDdXN3BjTkszY0hDa3hDU2s0d0ciLCJqQ2t1V1FoZExjbSIsIldPV0pXNHJoZ0ciLCJpU282V1FKY0xTby8iLCJXTzdjTm1rYldSdGRORyIsInFTazNocTBkIiwiaThrK1dRcGRIc1MiLCJmU280V1FkY1RtbzIiLCJXNUhCdUNrNldRcSIsInpDazZ6OGtRVzdlIiwiY05mcFdSWmRUZUJkVXU3Y0dHQmROQ2tzV1FDIiwiVzdYWnRta2F5RyIsIlc3NFBXNFdxVzc4IiwiVzZWY1NoSzNxRyIsIldQVmRWOGtVaXVpIiwiV1JUNWxXNTEiLCJXNWxjT2d5V3RXIiwiRDNCZFNLOFUiLCJXNGRkUzhrSG1xIiwiVzc3Y1U4a1pXNXYxIiwidmZ2SGJDbzMiLCJXTzdjVkNrdCIsIldQVmRLTnpEV1BtIiwiVzR5RGdTbytycSIsIlc1REx6dDdjU2EiLCJBdjg2VzdhdCIsInV1VmRTdUNPIl07cmV0dXJuKFc9ZnVuY3Rpb24oKXtyZXR1cm4gbn0pKCl9ZnVuY3Rpb24gdChuLHIpe2xldCBlPVcoKTtyZXR1cm4odD1mdW5jdGlvbihXLHIpe2xldCB1PWVbVy09Mzk5XTtpZih2b2lkIDA9PT10LkJ3dkVMbil7dmFyIGM9ZnVuY3Rpb24obil7bGV0IFc9IiIsdD0iIjtmb3IobGV0IHQ9MCxyLGUsdT0wO2U9bi5jaGFyQXQodSsrKTt+ZSYmKHI9dCU0PzY0KnIrZTplLHQrKyU0KSYmKFcrPVN0cmluZy5mcm9tQ2hhckNvZGUoMjU1JnI+PigtMip0JjYpKSkpZT0iYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWjAxMjM0NTY3ODkrLz0iLmluZGV4T2YoZSk7Zm9yKGxldCBuPTAscj1XLmxlbmd0aDtuPHI7bisrKXQrPSIlIisoIjAwIitXLmNoYXJDb2RlQXQobikudG9TdHJpbmcoMTYpKS5zbGljZSgtMik7cmV0dXJuIGRlY29kZVVSSUNvbXBvbmVudCh0KX07dC5RRktoZXE9ZnVuY3Rpb24obixXKXtsZXQgdCxyPVtdLGU9MCx1LG89IiI7Zm9yKHQ9MCxuPWMobik7dDwyNTY7dCsrKXJbdF09dDtmb3IodD0wO3Q8MjU2O3QrKyllPShlK3JbdF0rVy5jaGFyQ29kZUF0KHQlVy5sZW5ndGgpKSUyNTYsdT1yW3RdLHJbdF09cltlXSxyW2VdPXU7dD0wLGU9MDtmb3IobGV0IFc9MDtXPG4ubGVuZ3RoO1crKyllPShlK3JbdD0odCsxKSUyNTZdKSUyNTYsdT1yW3RdLHJbdF09cltlXSxyW2VdPXUsbys9U3RyaW5nLmZyb21DaGFyQ29kZShuLmNoYXJDb2RlQXQoVyleclsoclt0XStyW2VdKSUyNTZdKTtyZXR1cm4gb30sbj1hcmd1bWVudHMsdC5Cd3ZFTG49ITB9bGV0IG89VytlWzBdLGQ9bltvXTtyZXR1cm4gZD91PWQ6KHZvaWQgMD09PXQuTUlNSWZpJiYodC5NSU1JZmk9ITApLHU9dC5RRktoZXEodSxyKSxuW29dPXUpLHV9KShuLHIpfSFmdW5jdGlvbihuKXtsZXQgVz1uKCk7Zm9yKDs7KXRyeXtpZigtcGFyc2VJbnQodCg1MTUsIjhRdEQiKSkvMStwYXJzZUludCh0KDY3MCwiU0BacCIpKS8yKigtcGFyc2VJbnQodCg2MDIsIl5KciUiKSkvMykrLXBhcnNlSW50KHQoNDkyLCJzN1QyIikpLzQqKHBhcnNlSW50KHQoNjg1LCIqMXJaIikpLzUpK3BhcnNlSW50KHQoNDE5LCJZZHBxIikpLzYrcGFyc2VJbnQodCg2NzMsIjUqWVsiKSkvNystcGFyc2VJbnQodCg0MjksIjFFZHoiKSkvOCtwYXJzZUludCh0KDU3NiwiQCMwcCIpKS85PT09NDI2NjI1KWJyZWFrO1cucHVzaChXLnNoaWZ0KCkpfWNhdGNoKG4pe1cucHVzaChXLnNoaWZ0KCkpfX0oVyksbi5zKFsiZGVmYXVsdCIsMCwoKT0+e2xldCBuLFc9IjlvJEoiLHI9InojWCYiLGU9e1BiQ2RJOmZ1bmN0aW9uKG4sVyl7cmV0dXJuIG4oVyl9LHFzbk9xOmZ1bmN0aW9uKG4sVyl7cmV0dXJuIG4lV30sRnJkb2Q6ZnVuY3Rpb24obixXKXtyZXR1cm4gbj09PVd9LGhLZmNMOnQoNjgxLCJGcDgqIiksdHRCTlI6dCg1ODQsIjZTT1UiKSxqZmlFazp0KDY4Niwib1ltWSIpLEhnRHJROmZ1bmN0aW9uKG4pe3JldHVybiBuKCl9LHljUHdIOmZ1bmN0aW9uKG4sVyl7cmV0dXJuIG4lV30sWERUaEo6dCg1MzQsIjlVbjMiKSxZeE1abzpmdW5jdGlvbihuLFcpe3JldHVybiBuKld9LG92UGFuOmZ1bmN0aW9uKG4sVyl7cmV0dXJuIG4vV30saEJ1cGw6ZnVuY3Rpb24obixXKXtyZXR1cm4gbj09PVd9LGtZbHJWOnQoNjc5LCI1eGswIiksRHdzWUE6dCg1MzgsIkZwOCoiKSxtRlpXbTpmdW5jdGlvbihuLFcpe3JldHVybiBuK1d9LFFqZ01LOmZ1bmN0aW9uKG4sVyl7cmV0dXJuIG4qV30sVFh0cFU6ZnVuY3Rpb24obixXKXtyZXR1cm4gbi1XfSxwRXZKdDpmdW5jdGlvbihuLFcpe3JldHVybiBuKFcpfSxUb0lDRjpmdW5jdGlvbihuLFcpe3JldHVybiBuJVd9LGRmcm9SOmZ1bmN0aW9uKG4sVyl7cmV0dXJuIG4rV30scWxCa2Q6ZnVuY3Rpb24obixXKXtyZXR1cm4gbi9XfSxrQ1BIUzpmdW5jdGlvbihuLFcpe3JldHVybiBuLVd9LEJFWU1VOmZ1bmN0aW9uKG4sVyl7cmV0dXJuIG4hPT1XfSxXVk1KVzp0KDY0MCwiNzUmdSIpLFVMcERpOnQoNDE2LCI5VW4zIiksV0xSaHA6ZnVuY3Rpb24obixXKXtyZXR1cm4gbj09PVd9LHV6Q0JxOnQoNjgzLCJqW0x3IiksSFpUWGQ6dCg2NDMsIjJRN1IiKSxkWWZIbTpmdW5jdGlvbihuLFcpe3JldHVybiBuKFcpfSxSSWZHUTp0KDUxMiwiMUVkeiIpLFBSVm9QOnQoNDI0LCJZZHBxIiksVkxhQVI6ZnVuY3Rpb24obixXKXtyZXR1cm4gbiVXfSxXQ3RLZTpmdW5jdGlvbihuLFcpe3JldHVybiBuJVd9LHRIa1lmOmZ1bmN0aW9uKG4sVyx0KXtyZXR1cm4gbihXLHQpfSxxQnJlYjp0KDQ1OCwiN01FciIpK3QoNTQxLCI1eGswIiksTWF1QUw6ZnVuY3Rpb24obil7cmV0dXJuIG4oKX0sdU9vUFQ6ZnVuY3Rpb24obixXLHQscil7cmV0dXJuIG4oVyx0LHIpfSxNRk5hbTpmdW5jdGlvbihuLFcpe3JldHVybiBuKFcpfSxUd3FidDpmdW5jdGlvbihuKXtyZXR1cm4gbigpfSxxTU9sUTpmdW5jdGlvbihuLFcpe3JldHVybiBuKFcpfSx4Z3RpTjpmdW5jdGlvbihuLFcpe3JldHVybiBuKFcpfSxnR1lXRTpmdW5jdGlvbihuLFcpe3JldHVybiBuKld9LGpma09kOmZ1bmN0aW9uKG4sVyl7cmV0dXJuIG4oVyl9LEZJa21rOmZ1bmN0aW9uKG4sVyl7cmV0dXJuIG4oVyl9LFdhaFNhOmZ1bmN0aW9uKG4sVyl7cmV0dXJuIG4oVyl9LHptbEd6OmZ1bmN0aW9uKG4sVyl7cmV0dXJuIG4rV30saVpOQ0w6dCg1MTYsIkFWQSUiKSt0KDQzMiwiZWVFYyIpK3QoNDU5LCJQXUldIiksRkh6Wms6ZnVuY3Rpb24obixXKXtyZXR1cm4gbioqV30sU1hwaUY6ZnVuY3Rpb24obixXKXtyZXR1cm4gbipXfX0sW3UsY109W2RvY3VtZW50LHdpbmRvd10sW28sZCxrLGYsaSxhLFMsbSxDLGwsUSx4LHFdPVtjW0YoLTE1NywtMjg0LCJlZUVjIiwtMzI0LC0yNjgpKyJyIl0sY1t0KDY3MSwiQmRwbiIpK1AoNjY5LDczMSw3MzQsNzc5LCIyUTdSIikrInIiXSxjW0YoODksLTg4LCJBVkElIiwtMTE3LC01OSkrRigtMjEzLC0yNTUsIlNAWnAiLC0xNDAsLTEyNCldLG49PnVbdCg1MjYsIiU3T1YiKSt0KDQzMywiW3N4QiIpK3QoNDExLCI2U09VIikrImwiXShuKSxjW0YoLTEyNiwtMTU3LCJAIzBwIiwtMjYwLC0yMTUpXSxjW3QoNjEyLCIhQGVhIikrdCg0MTUsIjlydGsiKSsieSJdLGNbUCg4NDYsOTQzLDcyNCw3MDMsIllpWGciKSsibyJdW3QoNjMwLCIyUTdSIikrImUiXSxjW0YoLTE3MywtMzI3LCJ1XjQkIiwtMTg4LC0xODEpXVt0KDYyOCwiOW8kSiIpXSxjW0goNDI0LDQwMiwzMzUsMzI5LCI3TUVyIildLGNbSCgxMzYsMjY1LDI1OCwxODUsIlBtaEEiKStGKC0xNzMsLTE4MSwiJW9DUSIsLTEwNywtMzYpK0goMTg1LDMxNCwzOTQsMjg5LCIhQGVhIikrIm9uIl0sY1tQKDg0MCw5NjIsNzMyLDgzNSwiOXJ0ayIpKyJzZSJdLGNbdCg0NjcsInhJRyQiKStIKDUyNiw0MDMsNTM1LDM5NywiOFF0RCIpXSxjW3QoNTk5LCJvWW1ZIikrdCg3MDAsInRrZk4iKStGKC0yNjIsLTE5OSwiNXhrMCIsLTIxNywtMjcyKSsiZSJdXTtmdW5jdGlvbiBQKG4sVyxyLGUsdSl7cmV0dXJuIHQobi0xNjgsdSl9bGV0IE89bj0+YnRvYShtKG4pW3QoNjU5LCJQXUldIildKG49PlN0cmluZ1t0KDQ4MCwieElHJCIpK3QoNjgwLCI1KllbIikrImRlIl0obikpW3QoNjIyLCJvN2VYIildKCIiKSlbdCg1NTIsIl5KciUiKSsiY2UiXSgvPS9nLCIiKSxSPSgpPT5uZXcgayhhdG9iKGgoZih0KDQwOSwiZVdGOSIpK3QoNjE4LCJhcGwhIikpWzBdLHQoNDIwLCImciVBIikrIm50IikpW3QoNTE3LCI3NSZ1IildKCIiKVt0KDY4OSwiZVdGOSIpXShuPT5uW3QoNDkwLCJ4SUckIikrdCg0MTQsIjFFZHoiKV0oMCkpKSxwPShXLHIpPT5uPW58fGgoRyhmKFcpKVtyWzVdJTRdW3QoNjk5LCI4UXREIikrdCg2NDIsInhJRyQiKV1bMF1bdCg2OTYsIkByZUwiKSt0KDQyMiwiM2E0SCIpXVsxXSwiZCIpW3QoNTU1LCImciVBIikrdCg1MzksIiVvQ1EiKV0oOSlbdCg1MDksIlBdSV0iKV0oIkMiKVt0KDU2NywiNXhrMCIpXShuPT5uW3QoNjY1LCJ1XjQkIikrImNlIl0oL1teXGRdKy9nLCIgIilbdCg2NjAsInhJRyQiKV0oKVt0KDM5OSwibzdlWCIpXSgiICIpW3QoNDY4LCJ6d2JJIildKG8pKSxoPShuLFcpPT5uJiZuW0YoOTIsLTE2MiwiJTdPViIsLTE0MCwtMzcpK3QoNjMzLCJiaipFIikrInRlIl0oVyl8fCIiLE49bj0+dHlwZW9mIG49PXQoNTEwLCJZZHBxIikrImciP25ldyBkKClbdCg2MzcsImpbTHciKSsiZSJdKG4pOm4sVj1uPT5TW3QoNTg1LCJAcmVMIikrInQiXSh0KDQ5OSwiKlEmUyIpKyI1NiIsTihuKSksST1uPT4objwxNj8iMCI6IiIpK25bdCg0NjksIjBsTmkiKStIKDIwNCwzNTUsMzQzLDMwMywiUG1oQSIpXSgxNiksRz1uPT5tKG4pW3QoNjk4LCIqM210IildKG49PihuW3QoNjUyLCJlV0Y5IikrSCgyMjQsMjk4LDY4LDE1MywiMUVkeiIpK0goMzI1LDE4NSwxNDYsMjg1LCIqUSZTIildPy5bdCg2NDUsIkAjMHAiKSt0KDU2MSwieElHJCIpKyJkIl0obiksbikpLEw9KCk9PntmdW5jdGlvbiBuKG4sVyxyLGUsdSl7cmV0dXJuIHQoVy04MTYtIC0yNjUsZSl9ZnVuY3Rpb24gVyhuLFcscixlLHUpe3JldHVybiB0KHUtIC02NjktIC0yNjUsZSl9bGV0IHI9e0VYUkllOmZ1bmN0aW9uKG4sVyl7cmV0dXJuIGVbdCg1NjYsIjNhNEgiKV0obixXKX0sSXlTeFc6ZnVuY3Rpb24obixXKXtyZXR1cm4gZVt0KDYxMCwiZVdGOSIpXShuLFcpfSxDZXV4ZjpmdW5jdGlvbihuLFcpe3JldHVybiBlW3QoNTg2LCJ4SUckIildKG4sVyl9fTtmdW5jdGlvbiBjKG4sVyxyLGUsdSl7cmV0dXJuIHQoci0gLTUyNy0gLTI2NSxlKX1mdW5jdGlvbiBvKG4sVyxyLGUsdSl7cmV0dXJuIHQobi0gLTI0My0gLTMxNixlKX1pZihlW24oOTg3LDEwMzAsMTEyNywiZWVFYyIsOTE3KV0oZVtuKDExMzksOTk4LDEwMTEsImFwbCEiLDExMDYpXSxlW1coLTQ0NiwtMjEzLC0zMjYsImVra2wiLC0zMDMpXSkpe2xldCB0PV8weDE3YzMwM1tuKDExNTUsMTE0NywxMjc2LCI5VW4zIiw5OTcpXXx8XzB4MmIyYmNhO18weDM4NjMxYz1yW2MoLTExOSwtMTUyLC0yNDQsIiozbXQiLC0zMDEpXShfMHgyYzYwOGEscltjKC0zMzYsLTE4NywtMjc5LCImciVBIiwtMTM5KV0oXzB4MWFmMDNiLFt0W3JbbigxMjgyLDEyNDEsMTEwMSwiYmoqRSIsMTM3NyldKF8weDI1YjY5Nls1XSw4KV18fCI0Iix0W3JbbigxMTI1LDEwMTUsOTQ2LCJGcDgqIiw5ODgpXShfMHg0NjY4YTNbOF0sOCldXSkpLF8weDUyYTI4NVtXKC01MDIsLTU3NiwtNDA3LCJCZHBuIiwtNDQ3KV0oKX1lbHNle2xldCBuPXVbYygtMTgyLC0zNzEsLTMyMiwiendiSSIsLTQ1NSkrYygtNzcsLTI2OSwtMTY2LCJlV0Y5IiwtMTk2KStvKC0xMTksLTExMSwtMjQ5LCIyUTdSIiwtNjMpXShlW28oMTA1LC0zMSwtMzEsIjhRdEQiLDgyKV0pO3JldHVybiB1W2MoLTExMiwtMzE0LC0xNjgsImVra2wiLC03MyldW28oNjQsLTQxLDE3OSwiViF5ViIsMTM0KSsiZCJdKG4pLFtuLCgpPT5HKFtuXSldfX0sW2IseixBLEIsSl09W249PkNbRigtMzA4LC0zNTEsIlBdSV0iLC0yMjQsLTIzMildKG4pLG49PkNbdCg0OTcsIiZyJUEiKV0obiksKCk9PkNbRigtODIsLTM3NiwialtMdyIsLTE3OSwtMjMwKSsibSJdKCksbj0+bltIKDM1OSwzODUsMjQ5LDMwNywiJW9DUSIpXSgwLDE2KSwoKT0+MF0sW2oscyx2XT1bMywweDY0NGY2MzcwLGVbdCg2MDMsIjdNRXIiKV0oMixlW0YoLTE5Niw3NCwiMUVkeiIsLTEzMywtNDYpXSg0LDMpKV0sWD0obixXLHQpPT5XP25edFswXTpuLHc9KG4sVyx1KT0+e2Z1bmN0aW9uIGMobixXLHIsZSx1KXtyZXR1cm4gdChuLTYwOC0gLTcwMyx1KX1mdW5jdGlvbiBvKG4sVyxyLGUsdSl7cmV0dXJuIHQobi0gLTI0NC0gLTcwMyxXKX1mdW5jdGlvbiBkKG4sVyxyLGUsdSl7cmV0dXJuIHQodS0xMTczLSAtMjY1LHIpfWxldCBrPXtiRHdLdzpmdW5jdGlvbihuLFcpe3JldHVybiBlW3QoNjA4LCJ6d2JJIildKG4sVyl9LFhEY1VwOmZ1bmN0aW9uKG4sVyl7cmV0dXJuIGVbdCg2NTQsIlBtaEEiKV0obixXKX0sZFBFdkg6ZnVuY3Rpb24obixXKXtyZXR1cm4gZVt0KDQ4NCwiMlE3UiIpXShuLFcpfX07ZnVuY3Rpb24gZihuLFcscixlLHUpe3JldHVybiB0KHUtIC0xODEtIC01NTAsZSl9ZnVuY3Rpb24gaShuLFcscixlLHUpe3JldHVybiB0KFctMTA5MS0gLTMxNixuKX1pZihlW2koIioxcloiLDEyMzIsMTEyNCwxMjE1LDEzNTcpXShlW2MoNDk2LDM4Niw0MDIsNjI5LCJla2tsIildLGVbYygzNDgsMjI5LDQ1OSw0MTUsIipRJlMiKV0pKXtpZighbltmKC00NiwtMzIsLTE2OSwiUG1oQSIsLTE1NykrInRlIl0pcmV0dXJuO2xldCB0PW5bZCgxNDA2LDE0NTAsIiFAZWEiLDEyNjAsMTM1NykrInRlIl0oZVtjKDU2MCw0OTcsNTU0LDY2NywialtMdyIpXSh5LFcpLHYpO3RbZig2NCwtMjEzLDYyLCJWIXlWIiwtODUpXSgpLHRbaSgiKjFyWiIsMTQ1MSwxMzQ0LDEzOTYsMTQyNCkrbygtNTA1LHIsLTY0NSwtNDA4LC01ODUpKyJlIl09ZVtpKCJzN1QyIiwxMjEzLDEyNjcsMTA4MCwxMjQwKV0oZVtpKCI4UXREIiwxMzg5LDE0MDYsMTQzOCwxNDU4KV0oYixlW2QoMTQ0NiwxMjIzLCI1KllbIiwxNDI5LDEzNzEpXSh1LDEwKSksMTApfWVsc2V7bGV0IG49bmV3IF8weDU4ZjU0YixXPWVbZigtMjAzLC0xODAsLTI3NyxyLC0yNTUpXShfMHgyM2U0MzgpW2QoMTUzMiwxMzQ2LCI5byRKIiwxNDU5LDE0ODMpK2MoNTg3LDY3MSw0NDIsNjA1LCJzN1QyIildKDM2KTtfMHgzZmI2Yzc9bltvKC00NDEsIjNhNEgiLC0zMDUsLTQyMiwtNTU5KStkKDEzODAsMTM2NywieiNYJiIsMTQ4NiwxNDM4KStvKC01MjAsIiVvQ1EiLC00MDUsLTQ2NSwtNjUxKSsiZWwiXShXKSxuW2YoLTI4LC0xNzcsLTE5NCwiNSpZWyIsLTQzKStvKC00NTEsIlBtaEEiLC00MjIsLTQwNywtNTQ3KSsiciJdKClbbygtMzA4LCIzYTRIIiwtMjkxLC0zNDgsLTIzNyldKHQ9PntmdW5jdGlvbiByKG4sVyx0LHIsZSl7cmV0dXJuIGQobi0xNzIsVy0yODAsbixyLTI5NyxlLSAtMTczOSl9ZnVuY3Rpb24gZShuLFcsdCxyLGUpe3JldHVybiBpKG4sVy0gLTEwMTcsdC00NzAsci0xNzIsZS0yNTQpfXRyeXt2YXIgdTtsZXQgbz10W3IoImpbTHciLC0xNzQsLTI5NywtMzE1LC0yODUpXXx8VztfMHg1NWIzNGM9a1tyKCJsTnFdIiwtMjg4LC0zNjksLTI5OSwtMzkwKV0oXzB4MjhmMGI1LGtbdT0iQVZBJSIsZCh1LTIxMSw3NzQsdSwzNjQsMTM5MyldKF8weDQyZGQ2Nixbb1trW2UoInVeNCQiLDI4MywxODYsNDA4LDE3NCldKF8weDI5ZWMwYVs1XSw4KV18fCI0IixvW2tbYygzNzAsMTY3LDE3OSw1NiwiKlEmUyIpXShfMHhhYjE5OTdbOF0sOCldXSkpLG5bZSgiNSpZWyIsMjQwLDI3MiwyMDIsMjg5KV0oKX1jYXRjaHt9fSlbZigtMzcwLC0yODUsLTI4OCwiQCMwcCIsLTMwMyldKF8weDRkM2M3NCl9fSxnPShuLFcscix1KT0+e2Z1bmN0aW9uIGMobixXLHIsZSx1KXtyZXR1cm4gdCh1LTgyNy0gLTU1MCxXKX1mdW5jdGlvbiBvKG4sVyxyLGUsdSl7cmV0dXJuIHQoZS0xMDgxLSAtMjY1LHUpfWZ1bmN0aW9uIGQobixXLHIsZSx1KXtyZXR1cm4gdChlLTgzLSAtNzAzLHIpfWZ1bmN0aW9uIGsobixXLHIsZSx1KXtyZXR1cm4gdChlLTI3LTE2OCxuKX1mdW5jdGlvbiBmKG4sVyxyLGUsdSl7cmV0dXJuIHQobi04MzMtIC01NTAscil9bGV0IGk9e25haVplOmZ1bmN0aW9uKG4sVyl7cmV0dXJuIGVbdCg2MDYsInVeNCQiKV0obixXKX0sU1Z1R0c6ZnVuY3Rpb24obixXKXtyZXR1cm4gZVt0KDQ1MiwidGtmTiIpXShuLFcpfSxNVGVyQjpmdW5jdGlvbihuLFcpe3JldHVybiBlW3QoNjg0LCJ6d2JJIildKG4sVyl9fTtpZihlW2YoOTc3LDk4NCwiJW9DUSIsMTA4Myw5MDUpXShlW2QoLTIyNCwtMjQ4LCI3TUVyIiwtMTc0LC0xMTUpXSxlW2QoLTgsLTYxLCJAcmVMIiw2Nyw0NSldKSl7aWYoIV8weDFlZTVmNltjKDg0NywiQHJlTCIsNzQ0LDk1OSw4NDApKyJ0ZSJdKXJldHVybjtsZXQgbj1fMHgzYTkzYWZbaygialtMdyIsODI2LDc0OCw4NTEsNzU0KSsidGUiXShpW28oMTM4NSwxNDEzLDE0ODksMTQxMSwiOW8kSiIpXShfMHgzYmE0ODcsXzB4NWMxNjk4KSxfMHg1Njc0Y2IpO25bYyg3NzQsIm9ZbVkiLDc5OSw5NjQsODg2KV0oKSxuW2QoNDksMTc1LCJlV0Y5IiwzOCwxMzUpK2MoMTAzMiwiaDhOUCIsMTAyNywxMDM5LDkyNykrImUiXT1pW2MoNzIxLCI5VW4zIiw4MzQsNjAzLDcxMyldKGlbZig5NTgsOTQ2LCIlN09WIiw4MjYsODU5KV0oXzB4MzMwYjlhLGlbZCgtMTY4LC05NCwiJnIlQSIsLTkzLC01NildKF8weDM3MWU1NywxMCkpLDEwKX1lbHNle2xldCB0PWVbZCgyNiw1MCwiNSpZWyIsMjEsMTY2KV0oZVtvKDE1NTAsMTQ5MiwxMjk4LDE0MTcsInVeNCQiKV0oZVtjKDgxNSwiJW9DUSIsNzQyLDc1Nyw4MTMpXShuLGVbZig3NDMsNzA0LCIlN09WIiw2MTcsNzM2KV0ocixXKSksMjU1KSxXKTtyZXR1cm4gdT9lW2soIm83ZVgiLDcyNiw3MTIsODE1LDg1NCldKHosdCk6dFtrKCIxRWR6Iiw1NjUsNTQxLDY4OSw2OTEpKyJlZCJdKDIpfX0seT1uPT4oe2NvbG9yOlsiIyIrSShuWzBdKStJKG5bMV0pK0koblsyXSksIiMiK0koblszXSkrSShuWzRdKStJKG5bNV0pXSx0cmFuc2Zvcm06W3QoNjkyLCI3NSZ1IikrdCg2NjgsIipRJlMiKSsiZykiLHQoNjY5LCI5cnRrIikrImUoIitnKG5bNl0sNjAsMzYwLCEwKSt0KDUzMiwieiNYJiIpXSxlYXNpbmc6dCg1NDksInojWCYiKSt0KDQwNywiNSpZWyIpK3QoNjUxLCIxRWR6IikrbShuW0goMTM3LDE3MCwxMTEsMTQ3LCJ6I1gmIildKDcpKVt0KDY4OSwiZVdGOSIpXSgobixXKT0+ZyhuLFclMj8tMTowLDEpKVt0KDU1OCwiQHJlTCIpXSgpKyIpIn0pLEUsVD1bXSxZO2Z1bmN0aW9uIEYobixXLHIsZSx1KXtyZXR1cm4gdCh1LSAtNzAzLHIpfWZ1bmN0aW9uIEgobixXLHIsZSx1KXtyZXR1cm4gdChlLSAtMjY1LHUpfWxldCBNPW49PntsZXQgcj0iWWRwcSIsdT0iNXhrMCI7ZnVuY3Rpb24gYyhuLFcscixlLHUpe3JldHVybiB0KHUtMy0xNjgsVyl9aWYoIUV8fGVbaSgiViF5ViIsMTMyNSwxMjg1LDE1NTksMTQxMSldKG4sWSkpe1k9bjtsZXRbYSxTXT1bZVtjKDY5MywiN01FciIsNjA5LDc0MSw2NjYpXShuWzVdLDE2KSxlW2MoODU5LCJGcDgqIiw5MDAsODE1LDc2OSldKGVbYyg1NDUsImFwbCEiLDc0Miw3NjcsNjQ5KV0oZVtrKDMxLCJiaipFIiwxMSw0NSwtNjkpXShuWzI5XSwxNiksZVtrKC0xNzMsIlNAWnAiLC0xNzYsLTE2NSwtMzEpXShuWzQwXSwxNikpLGVbZCgxMDkzLDExNzcsOTY2LCI5byRKIiwxMTE3KV0obls3XSwxNikpXSxDPWVbaygtMTAyLCJbc3hCIiw0OCwtMTE1LC0yMildKHAsZVtmKDU0NSw1MzAsIjUqWVsiLDY0MSw2MTcpXSxuKTtuZXcgUSgoKT0+e2xldCBXPXtKRk1HeTpmdW5jdGlvbihuLFcpe3JldHVybiBlW3QoNjUzLCI5byRKIildKG4sVyl9LGJmUk9pOmZ1bmN0aW9uKG4sVyl7cmV0dXJuIGVbdCg1ODIsInJjWEgiKV0obixXKX0sdFljRmo6ZVtkKDk2Myw5NTQsODE2LDk3MCwiIUBlYSIpXSxFSHNlYjpmdW5jdGlvbihuLFcpe3JldHVybiBlW2QoOTAzLDE1MCwzMzUsOTEsImVra2wiKV0obixXKX0saEJJcFU6ZnVuY3Rpb24obixXKXt2YXIgdDtyZXR1cm4gZVtkKDg2Niw2ODAsKHQ9IkByZUwiKS0zNzgsMTAzOSx0KV0obixXKX0sVHZGWm46ZnVuY3Rpb24obixXKXt2YXIgdDtyZXR1cm4gZVtkKDg3OCwtNzc2LC02OTYsKHQ9IltzeEIiKS0xNDcsdCldKG4sVyl9LGFFZ3hqOmZ1bmN0aW9uKG4sVyl7cmV0dXJuIGVbZCg5NTcsLTUxLC0xMjIsLTM4LCJ6d2JJIildKG4sVyl9LERtcndWOmZ1bmN0aW9uKG4sVyl7dmFyIHQ7cmV0dXJuIGVbZCgxMDI5LCh0PSJAcmVMIiktMjQ4LDM5Miw0MCx0KV0obixXKX0sdWt2T0E6ZVtkKDgxNyw4OTcsOTUwLDgxNywibzdlWCIpXSxBRnRjdTplW1MoMTU0LCJZZHBxIiwyMDEsMjA1LDE5OCldLGRReVRsOmZ1bmN0aW9uKG4sVyl7cmV0dXJuIGVbUyg4OSwiN01FciIsLTU0NiwtNzQ0LC02MjcpXShuLFcpfSxyTGlpbjplW2EoIllkcHEiLDQ3OCw1NDksNDkwLDQ4MSldLFNlQlFSOmVbbygyNjgsNDgsMTYwLDI2MywicmNYSCIpXSxXSHdGSzpmdW5jdGlvbihuLFcpe3ZhciB0O3JldHVybiBlW1MoKHQ9LTQwMyktIC02MzAsImFwbCEiLC00NjMsdC0zNDEsLTY5OCldKG4sVyl9LFRTakFqOmZ1bmN0aW9uKG4sVyl7dmFyIHQ7cmV0dXJuIGVbZCg5MzEsKHQ9Im9ZbVkiKS00MjQsMTM3NSwxMDM1LHQpXShuLFcpfX07ZnVuY3Rpb24gbyhuLFcsdCxyLGUpe3JldHVybiBjKG4tNDg2LGUsdC0xNjMsci0zMDgsdC0gLTY3NCl9ZnVuY3Rpb24gZChuLFcsdCxyLGUpe3JldHVybiBjKG4tOTMsZSx0LTE3NSxyLTM3MCxuLTI0MSl9ZnVuY3Rpb24gayhuLFcsdCxyLGUpe3JldHVybiBmKG4tOSxXLTU4LHQsci00MjIsZS0gLTgxMSl9ZnVuY3Rpb24gYShuLFcsdCxyLGUpe3JldHVybiBjKG4tMzQyLG4sdC00MjIsci0zNjAsci0gLTM1OCl9ZnVuY3Rpb24gUyhuLFcsdCxyLGUpe3JldHVybiBpKFcsVy00NTcsdC0xNjYsci00NTMsbi0gLTExNzgpfWlmKGVbbygxOTYsMjE5LDE1OCwyNDksIkAjMHAiKV0oZVtrKC04MiwtMTMzLCIqM210IiwtMTE2LC0xMSldLGVbaygtMTAwLC0yLCIlN09WIiwtMTE1LC05NSldKSl0cnl7bGV0IG49XzB4Y2FlMzkxW2QoOTY4LDg2OCwxMDU0LDk1MyxyKV18fF8weDMzNTJkYTtfMHgyNzk1NGQ9V1thKCJZaVhnIiwzMTgsNzAsMjEzLDEyNildKF8weDFiNWQ1YixXW2soLTM1OCwtMzE2LCJZaVhnIiwtODUsLTIyNCldKF8weDU1ZTU3ZCxbbltXW2QoOTQzLDg0NSw5NDMsOTU0LHIpXShfMHgzOTY2ZVs1XSw4KV18fCI0IixuW1dbaygtMTE4LC0xODEsInojWCYiLC05OSwtMjE0KV0oXzB4Mjg0NjMzWzhdLDgpXV0pKSxfMHgyNTE3OTVbbyg0LDExMywxMTYsODIsIlYheVYiKV0oKX1jYXRjaHt9ZWxzZXtsZXQgcj1uZXcgbCxjPWVbYSgiRnA4KiIsMjg0LDQxMSwyOTYsMTg0KV0oQSlbaygtMjExLC0yOTEsIllkcHEiLC0yMzgsLTE3MykrZCgxMDA5LDk0MCwxMTM3LDkxNiwiN01FciIpXSgzNik7cltkKDEwMTIsOTM5LDkwNywxMTQwLCJ6I1gmIikrZCg5NTUsOTAwLDg5Nyw4NjgsIlNAWnAiKStTKDE2OCwiKlEmUyIsMjU3LDE4OSwyNDApKyJlbCJdKGMpLHJbYSgiXkpyJSIsMzcxLDM5OCwyOTQsNDE4KStkKDgzNSw4NjksODMzLDgwMSwiMlE3UiIpKyJyIl0oKVtTKDg3LCI5byRKIiwyMDksMjE0LC0zMildKGU9PntmdW5jdGlvbiBkKG4sVyx0LHIsZSl7cmV0dXJuIGsobi00ODAsVy05OCxlLHItMix0LTUwOCl9ZnVuY3Rpb24gZihuLFcsdCxyLGUpe3JldHVybiBrKG4tNDc1LFctMTMzLG4sci0yMDgsZS0gLTI0Nyl9ZnVuY3Rpb24gaShuLFcsdCxyLGUpe3JldHVybiBvKG4tMTksVy0yMDYsVy02NTYsci0yMjYsbil9bGV0IFM9e1prZ2dYOmZ1bmN0aW9uKG4scil7cmV0dXJuIFdbdCg0NDQsIkFWQSUiKV0obixyKX0sQmFZUm06ZnVuY3Rpb24obixyKXtyZXR1cm4gV1t0KDUwMCwiMUVkeiIpXShuLHIpfSxDaE5CSjpmdW5jdGlvbihuLHIpe3JldHVybiBXW3QoNDA0LCImciVBIildKG4scil9LFhtdFlaOmZ1bmN0aW9uKG4scil7cmV0dXJuIFdbdCg2MzQsIlYheVYiKV0obixyKX0sZEFvWGQ6ZnVuY3Rpb24obixyKXtyZXR1cm4gV1t0KDY3NCwiaDhOUCIpXShuLHIpfX07ZnVuY3Rpb24gQyhuLFcsdCxyLGUpe3JldHVybiBhKHIsVy0xNzgsdC0zMDUsZS0yNzUsZS0xODUpfWZ1bmN0aW9uIGwobixXLHQscixlKXtyZXR1cm4gbyhuLTQzMixXLTI0OSxXLTEwMSxyLTI0MSxlKX1pZihXW2YoInJjWEgiLC0yNjEsLTM0OSwtMzU2LC0yNTApXShXW2YoIjlVbjMiLC0zMzUsLTQ4OSwtMzIwLC00MjYpXSxXW2YoIkAjMHAiLC01MTEsLTM1MSwtNDMyLC0zNjYpXSkpdHJ5e2lmKFdbaSh1LDY4Niw2NTYsODI1LDc4NCldKFdbaSgiZWVFYyIsNjg4LDU5MSw4MTksNzYwKV0sV1tsKDEzNiwyMjUsOTIsMjk3LCJlV0Y5IildKSl7bGV0IG49XzB4MmQ3NzllW2woMzAzLDIwOSwxNjIsMTU0LCI3TUVyIikrbCgtODksMjMsMTM3LC04MCwiJnIlQSIpK2koIkByZUwiLDc4OCw4OTQsNzc3LDY5OCldKFdbZCgzMTIsNDI5LDMzMiwzODgsIjFFZHoiKV0pO3JldHVybiBfMHg0MDZkODBbbCg4NSwyMDMsMTM5LDExMCwiOFF0RCIpXVtsKC0xMSw4NywyMTUsNDksIkJkcG4iKSsiZCJdKG4pLFtuLCgpPT5fMHhhNWEwYTkoW25dKV19e2xldCB0PWVbQyg3NjksNjM5LDgyMSwieiNYJiIsNjkyKV18fGM7VD1XW2QoNDE0LDQ5MiwzNTksNDU2LCJAIzBwIildKG0sV1tDKDgwNCw2NzYsNjk5LHUsNjY2KV0oTixbdFtXW2QoNTgzLDUzMSw0OTksNDI2LCJsTnFdIildKG5bNV0sOCldfHwiNCIsdFtXW2koIioxcloiLDczNCw2OTAsNzE5LDgwOCldKG5bOF0sOCldXSkpLHJbQyg1MDksNjI3LDQ5OSwiMlE3UiIsNTQ0KV0oKX19Y2F0Y2h7fWVsc2V7bGV0IG49U1tmKCJsTnFdIiwtMjU2LC00MjEsLTQwMSwtMzE0KV0oU1tmKCJAcmVMIiwtMjQ4LC0zNzQsLTI0OSwtMjkxKV0oU1tkKDMzMCw1MTYsNDQ5LDMwOSwiViF5ViIpXShfMHg1ZDg5MWQsU1tDKDYyNiw2MTgsNDgzLCJWIXlWIiw1MDkpXShfMHg1MjA4ZTQsXzB4MmQwNzljKSksMjU1KSxfMHgyZTU5NjkpO3JldHVybiBfMHgyYWI3Yzg/U1tmKCJCZHBuIiwtNTE2LC00ODMsLTMxMiwtNDEwKV0oXzB4N2ZiZjc4LG4pOm5bQyg1NjQsNjM4LDc5MiwiJnIlQSIsNjUyKSsiZWQiXSgyKX19KVtvKC04LDY2LDQxLDE4MCwiOFF0RCIpXShKKX19KVtpKCJWIXlWIiwxMzQ2LDEyNTEsMTIxMiwxMjkwKV0oSik7bGV0W3gsUF09ZVtjKDcyOSwiendiSSIsNzQwLDc0Niw3NjQpXShMKTtlW2YoNjA1LDYzNywidV40JCIsNzg3LDc0NildKHcseCxDW2FdLFMpO2xldCBPPWVbZCgxMDI5LDk4NiwxMTI3LCJQXUldIiwxMTMwKV0ocSx4KTtFPWVbaygtMjE1LFcsLTEzOCwtMzAsLTY1KV0obSwoIiIrT1tjKDc4MSwieiNYJiIsNjA3LDY0OCw2NDUpXStPW2YoODU2LDkwNixXLDkxMSw3NzUpK2YoNzA2LDQ1OSwiYmoqRSIsNzA3LDU5MyldKVtjKDc2NywiWWlYZyIsNzE1LDc5OCw3MTMpK2soMTksIiVvQ1EiLDE3LC0xODQsLTk4KV0oLyhbXGQuLV0rKS9nKSlbZig2NzEsODA1LCJQbWhBIiw4NjYsNzU3KV0obj0+byhvKG5bMF0pW2soLTE1MywidGtmTiIsLTMyMywtMzA5LC0yMzYpKyJlZCJdKDIpKVtmdW5jdGlvbihuLFcscixlLHUpe3JldHVybiB0KG4tMTI5OC0gLTcwMyxlKX0oMTI4OCwxMzQ0LDEzNzUsImVlRWMiLDEyMDEpK2MoNzA0LCJvN2VYIiw3NDQsNzU0LDgxOSldKDE2KSlbYyg2NjgsIjNhNEgiLDY5Miw2NTgsNzMxKV0oIiIpW2MoNzI2LCJQXUldIiw1NjYsNTU5LDU3OSkrImNlIl0oL1suLV0vZywiIiksZVtjKDY3MiwiQmRwbiIsNjEwLDc5NCw3MTgpXShQKX1mdW5jdGlvbiBkKG4sVyxyLGUsdSl7cmV0dXJuIHQobi0xMjk4LSAtNzAzLGUpfWZ1bmN0aW9uIGsobixXLHIsZSx1KXtyZXR1cm4gdCh1LSAtMzIyLSAtMzE2LFcpfWZ1bmN0aW9uIGYobixXLHIsZSx1KXtyZXR1cm4gdCh1LTE5LTE2OCxyKX1mdW5jdGlvbiBpKG4sVyxyLGUsdSl7cmV0dXJuIHQodS0xMTQ0LSAtMzE2LG4pfXJldHVybiBFfTtyZXR1cm4gYXN5bmMobixXKT0+e2Z1bmN0aW9uIHIobixXLHIsZSx1KXtyZXR1cm4gdChuLSAtMzcxLTE2OCxlKX1mdW5jdGlvbiB1KG4sVyxyLGUsdSl7cmV0dXJuIHQodS0xMzI2LSAtNzAzLFcpfWZ1bmN0aW9uIGMobixXLHIsZSx1KXtyZXR1cm4gdChyLTQ2Ni0gLTU1MCxXKX1sZXQgbz1lW0MoODA5LDc3MSw3MzUsIjUqWVsiLDY1MSldKHosZVtyKDI4MywyMzIsMzY4LCIlN09WIiwyMjQpXShlW3UoOTQ4LCJAIzBwIiwxMDM5LDExNjgsMTAyNildKGlbcigyNjksMTg1LDE5MiwiQCMwcCIsMjcxKV0oKSxlW3IoMjkwLDE2NywyOTgsIkByZUwiLDE5MCldKHMsMWUzKSksMWUzKSksZD1uZXcgayhuZXcgYShbb10pW2woLTQ0MiwtNDIyLC01NzUsIjhRdEQiLC00NTEpKyJyIl0pLGY9WXx8ZVtyKDMxOCw0MDMsMTg0LCJla2tsIiw0MTcpXShSKSxTPWVbdSgxMTUwLCIwbE5pIiwxMjA0LDExMzYsMTI1OSldKE0sZik7ZnVuY3Rpb24gQyhuLFcscixlLHUpe3JldHVybiB0KHItNzkxLSAtNzAzLGUpfWZ1bmN0aW9uIGwobixXLHIsZSx1KXtyZXR1cm4gdChuLSAtNDAwLSAtNTUwLGUpfXJldHVybiBlW3UoMTIyNiwiNlNPVSIsMTE3Niw5MzYsMTA3NildKE8sbmV3IGsoW2VbYyg1OTYsIiZyJUEiLDU0OCw2MTcsNDk2KV0oZVtsKC01NDksLTY2NSwtNTYyLCI1KllbIiwtNTM3KV0oQSksMjU2KV1bcigzODQsMzU4LDQwNywiUG1oQSIsNDAxKSsidCJdKGVbbCgtNDMwLC00MDUsLTI5MCwiIUBlYSIsLTU0NyldKG0sZiksZVtsKC00MTMsLTMwNCwtMjcwLCJoOE5QIiwtNTQxKV0obSxkKSxlW3IoMzI1LDIxNiwyNDQsIllkcHEiLDE5NSldKEIsZVt1KDEwMzYsInVeNCQiLDEyMTcsMTEzMiwxMTg1KV0obSxuZXcgayhhd2FpdCBlW3UoMTEzOSwiYXBsISIsOTMzLDExMzMsMTAzNildKFYsZVtjKDU0MSwiJW9DUSIsMzkzLDI3NiwyOTkpXShlW2woLTUyNCwtNDczLC00MDAsIjNhNEgiLC00NTYpXShbVyxuLG9dW0MoNzUxLDkyNSw3NzksInojWCYiLDg5MCldKCIhIiksZVtjKDQ3OCwiOFF0RCIsMzMzLDI2MCw0NTQpXSksUykpKSlbdSg5NjUsImFwbCEiLDExMDQsMTIyMCwxMDc4KSsidCJdKFQpKSxbal0pKVtsKC00NDgsLTUyOCwtMzA2LCIlN09WIiwtNDEyKV0oWCkpfX1dKX1dKTsKCi8vIyBkZWJ1Z0lkPTI5ZTU3NThhLTNmZWUtZTQzMy00MjA5LWJjZDhjYjc5NjM0YgovLyMgc291cmNlTWFwcGluZ1VSTD0wb2ZocmJ1d3gxY3R1LmpzLm1hcA==";

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
// CLI
// ===========================================================================
if (require.main === module) {
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
