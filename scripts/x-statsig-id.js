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

// `.r-48wmo` 的 4 条 svg path d(grok 用 Q[5]%4 选其一作 m 矩阵源)。
const M_PATHS = [
  "M 10,30 C 15,55 198,106 97,15 h 200 s 21,190 23,117 C 248,97 164,115 61,189 h 203 s 174,85 21,167 C 216,17 30,97 117,247 h 48 s 88,156 200,181 C 167,253 15,112 92,26 h 39 s 75,225 173,115 C 125,116 8,248 37,38 h 31 s 77,198 249,160 C 94,155 96,1 197,94 h 210 s 255,145 206,203 C 164,124 160,217 230,61 h 185 s 121,152 8,83 C 62,14 127,65 97,68 h 43 s 8,37 156,72 C 17,175 55,158 41,137 h 76 s 133,139 153,239 C 121,221 127,50 120,44 h 225 s 159,228 47,232 C 82,86 230,148 149,217 h 133 s 157,27 229,187 C 195,139 217,19 112,181 h 44 s 127,129 32,255 C 150,221 74,234 81,179 h 83 s 105,210 200,126 C 68,135 69,90 198,135 h 133 s 236,251 175,42 C 200,27 186,226 18,63 h 247 s 73,114 121,38 C 240,254 227,84 8,178 h 25 s 3,121 229,62",
  "M 10,30 C 60,251 153,44 164,156 h 204 s 252,28 128,166 C 27,136 222,98 211,233 h 152 s 81,235 179,127 C 73,16 202,82 0,37 h 105 s 110,201 21,43 C 89,30 78,145 194,111 h 107 s 6,73 201,178 C 148,176 11,23 19,83 h 67 s 38,172 55,249 C 110,194 46,233 152,12 h 99 s 247,162 75,21 C 159,77 207,184 112,132 h 148 s 238,230 229,207 C 220,54 90,207 50,68 h 231 s 103,249 152,94 C 58,47 199,165 28,22 h 184 s 220,3 34,95 C 52,196 110,172 197,11 h 199 s 120,17 22,222 C 11,190 174,133 45,252 h 218 s 238,63 198,169 C 135,182 76,239 169,62 h 23 s 55,96 154,242 C 45,147 13,202 200,143 h 237 s 92,185 248,45 C 103,12 71,183 66,171 h 129 s 199,15 4,7 C 200,67 24,174 35,253 h 196 s 109,114 217,202 C 107,37 114,62 42,159 h 72 s 102,30 139,127",
  "M 10,30 C 150,30 184,16 5,238 h 157 s 21,226 39,11 C 214,137 183,181 132,176 h 87 s 178,239 222,153 C 114,12 214,173 156,116 h 243 s 15,203 221,151 C 113,80 173,97 84,219 h 135 s 135,248 51,178 C 200,195 156,255 154,190 h 228 s 126,249 98,157 C 47,69 123,99 27,71 h 36 s 78,178 104,36 C 40,9 117,46 54,183 h 130 s 225,52 136,161 C 223,72 250,89 183,35 h 103 s 242,242 89,231 C 133,140 46,34 137,183 h 109 s 35,60 113,144 C 92,135 104,184 4,52 h 39 s 179,154 232,229 C 235,61 39,231 195,30 h 43 s 95,84 55,112 C 66,30 192,213 222,255 h 196 s 57,217 236,65 C 83,173 220,146 192,132 h 89 s 81,103 248,10 C 79,76 39,241 154,7 h 3 s 130,248 25,122 C 215,43 167,175 232,195 h 47 s 29,59 99,128 C 226,173 52,82 114,162 h 141 s 220,206 47,237",
  "M 10,30 C 193,19 131,194 25,157 h 56 s 40,169 121,149 C 122,251 95,34 28,57 h 0 s 149,251 182,61 C 248,104 38,184 138,145 h 78 s 67,193 87,248 C 236,212 210,172 35,255 h 105 s 145,182 61,58 C 171,133 145,29 218,213 h 182 s 144,52 168,36 C 115,54 236,244 196,42 h 184 s 201,250 96,219 C 188,219 191,34 139,77 h 53 s 243,45 35,92 C 146,196 252,62 104,73 h 179 s 50,208 147,246 C 70,233 90,79 53,16 h 84 s 71,253 194,101 C 60,252 173,191 191,89 h 94 s 15,199 154,103 C 169,87 207,71 40,206 h 94 s 216,85 78,107 C 101,146 64,105 165,57 h 254 s 223,232 165,251 C 215,137 58,126 124,58 h 208 s 49,6 154,169 C 111,32 143,224 226,201 h 180 s 5,187 255,130 C 108,191 104,106 85,240 h 48 s 228,88 164,157 C 134,115 223,226 83,104 h 26 s 106,72 4,133",
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
const SIG_CHUNK_B64 = "OyFmdW5jdGlvbigpe3RyeSB7IHZhciBlPSJ1bmRlZmluZWQiIT10eXBlb2YgZ2xvYmFsVGhpcz9nbG9iYWxUaGlzOiJ1bmRlZmluZWQiIT10eXBlb2YgZ2xvYmFsP2dsb2JhbDoidW5kZWZpbmVkIiE9dHlwZW9mIHdpbmRvdz93aW5kb3c6InVuZGVmaW5lZCIhPXR5cGVvZiBzZWxmP3NlbGY6e30sbj0obmV3IGUuRXJyb3IpLnN0YWNrO24mJigoZS5fZGVidWdJZHN8fCAoZS5fZGVidWdJZHM9e30pKVtuXT0iMWRlY2Q4YmItMmE3Mi0yMmI1LThlMGQtMmQ3YzQ5NWNiZWNiIil9Y2F0Y2goZSl7fX0oKTsKKGdsb2JhbFRoaXMuVFVSQk9QQUNLfHwoZ2xvYmFsVGhpcy5UVVJCT1BBQ0s9W10pKS5wdXNoKFsib2JqZWN0Ij09dHlwZW9mIGRvY3VtZW50P2RvY3VtZW50LmN1cnJlbnRTY3JpcHQ6dm9pZCAwLDE2NDVlMyxXPT57InVzZSBzdHJpY3QiO2Z1bmN0aW9uIG4oKXtsZXQgVz1bIkJMVHRXT0NXIiwiVzVOY0tTazNoMjQiLCJXT3BjUWF4ZElTb04iLCJXNTQxVzVtIiwiV1FGZE5zeGNTbW9seUNvZlc1UmNOV2UiLCJuWjkxVzZ4ZFBhIiwiY1NvQ3R1bGNTRyIsInRTazZXUFciLCJXUlJkS0NrQm9zYSIsIm9abURXNGp5IiwiV1I5WFc3amRDVyIsIlc0OStvaG1HIiwiVzR6b1dSM2NQcSIsIlc0em1GOG81Vzd1IiwiV1JuL1c3VHpFcSIsIldSS0JXN2hkVjFLc25mNE10Q29SIiwiV1FWY1Q4a3hFd3EiLCJXNmJvdVNvTlc1RyIsIlc0NEdXNTF6VzdpIiwiaEhoZE9nZGNWcSIsIlc3YTFXNHpTVzZDIiwiZ0g0blc1cjFsU29uVzdMTHU4aytCcSIsImtibGRSMUZjSXEiLCJXUlZjUENvblc0NFUiLCJXNnhkVTBtOHVHIiwiVzdCY0hDb29XUVpkUnEiLCJXUTNkSm1rNG1zVyIsIldQdGNRWk5kSkNvVyIsIlc3ZkZXUmxkVE5xIiwiVzR0Y1VTazlXT3ZaIiwiQjJOY0xnL2NMcSIsIlc1L2NIU2tOV1JIcyIsIlc1TmNVQ2t1V1BmeiIsIlc1YStXNGJDVzVlIiwiVzZKY0k4b0VqQ28zIiwicjhvZEZTa0VXUEsiLCJXNmhkVTB1UXNhIiwic3FuMldQVzkiLCJqU291YzFqeCIsInNta1l2S0QyIiwiV1FOY0tta2xXTzdjTmEiLCJnY2pXIiwiYm1rR1c3QmNJOG8xIiwiV1BWZFNta3hodFMiLCJXUmhkVmJ4Y05xIiwiVzZ0ZEsyUzF6cSIsIlc0ZGNIU2s1V1JuRCIsIkNta2xqcSIsIldSQmNUbW9oVzRTLyIsIldPZGNNdkRzRHEiLCJXNHRkSjJlM3NXIiwidEtqc1dPUzIiLCJXNmxkTDI1b3htb1d2Q2tvalNrd1dPYSIsInlTazNXT2EiLCJ4Q284ZHhQdyIsIldPZGRLQ2s1bnNTIiwiVzRSY09Db21XUnBjUEciLCJXNGZIV1BuaVdQVyIsIlc1bnJXN1dZRGEiLCJjc0ZkSXVsY0lXIiwiV1BKY0lDa1VXT2xjUHEiLCJubW9ZaXh6eCIsIlc2M2NHZTVjclciLCJXT0Q1V1BkY1JhIiwiVzZiTVc0L2NNbW9HIiwiV09oY0laUmRQOG9WIiwiV09EK1dRQmNUU2txIiwiVzR6SldPWGFXUmUiLCJXUHI4V09LaFdSdXJlbW83blNrdVdQZGRKRyIsIldPTCtXUHBjUVNrSyIsIldRUGRXT3ZVVzR5IiwiV1JoZFJYWmNLbW9uIiwiVzdUK1c2bGNMQ29iIiwiVzZ6WkE4b2RXNWUiLCJXNkgxQ21vQyIsIldSL2NWbW9MVzZXMyIsImtjdUhXN0RwIiwiVzVYUFc3MGtCRyIsImpkM2RJTHRjSVciLCJyU2s0V09xIiwibXJPa1c2ckwiLCJBOGtnV1BSZEc4a0YiLCJEOG9xVzd2Nm5xIiwiVzRUeFdRdnMiLCJXNmJQVzdlIiwiZFNramw4b3dXNVM0QzhrS2RTazdXUnhjTEciLCJoc1pjTjhrMVdRYSIsIlc3bGNWOGs3a2Z5IiwiV08zZFZta1VtSU8iLCJXNEwvV09xIiwiZUltRlc0YksiLCJXN2ZsV1J2c1c0eSIsIlc1MGpXNTExVzVDIiwiVzRQaXBXIiwiVzU3Y1FTb0twRyIsIkJOWmNJZ1JjR2EiLCJXNlpkTVNvRFc2SmRUQ2tlVzUxSFdPMWhXNUpjTHEiLCJXN05jSDhvcVdRTmRHcSIsImdjU2dXNnkiLCJybW9vekNrb1dPYSIsImhTb0dEdzdjUWEiLCJXN2pZZGM3Y1NXIiwiV1IzY01ta3VXUUpjU2EiLCJXUlpkUXFWY1BTb3YiLCJrc2RkSExKY0dhIiwiV1JaY1ZTb0FXNTREIiwiVzZuMENtb0ZXN0MiLCJXNmIwb3NGY1VXIiwiV09iMVdPdSIsImp4RmNReGxjSXZ1OSIsIlc3N2NMQ2s5IiwiV1BENFdPbSIsIngwdGNOZlZkSVciLCJXNGRjSG1rM1dSSyIsIkJTa3dXUEwzIiwia1NvRXQwQmNQcSIsIlc0bUlXNHI0IiwiVzVKY09oaGRLQ28wIiwiV1JUMHNtb2dXNzdkSW1vNiIsImFJamJXNjNkUHEiLCJicXErVzR6cCIsIlc1VmNIbW96V09KZEhXIiwibUo0TVc2UHEiLCJXNHhjTUNvdldPQmRORyIsImdjN2NSOGs1V1JLIiwiVzV6Rlc1M2NTU28zIiwicFl5RFc3YnkiLCJXNXJpV1FyN1dRZSIsIndDa0hlQ2tPVzVTIiwiRXFMMFdQTy8iLCJXNDF4dVNvdFc0ZSIsIlc3WFJuc1JjVUciLCJXUDhYQnZGZFBtb3VBaEJjSmVWZFMxVmNIYSIsIlc0WmNUOG9ub1NvYSIsIldSN2RTOGsycGFpIiwidzEvY1N4L2RNVyIsIlc1cmZqS0daIiwiVzRUZmRyRmNHYSIsIlc2OTFXNzA5V1FhIiwiVzZxclc2NTVXNUsiLCJXNDRVVzR2dlc2RyIsInFTb1JXUS9kVDhrQldSeGRKcTNjTDhreXdtb2xXUXhkT1ciLCJXUlRLVzdqWENXIiwiYVNrMVc2SmNRQ29pIiwienVaY1AzN2RPcSIsInhlenlXT08iLCJXNUdDVzRuSlc0OCIsIlc0OTJoVzdjVVciLCJXNUR1dThvL1c3dSIsInlTb1JXNlA4a2EiLCJXUE84VzRySVc0UyIsIldRWmNVbW83VzVTTyIsIldRZGNLU28rVzZhQyIsIndTazd3d0MiLCJBU29xVzdDIiwiV1FWZFFDa3prc2UiLCJXNG4rV08xb1dQbSIsIkI4b3FXN3ZDbmEiLCJXTy9jUUhWZEo4b2UiLCJXUVpjT0NrUXQyaSIsIlc0YVBXN1AvVzR5IiwiQmhKY0lOeGNIYSIsIlc1TDdXT1JjTnFPIiwiVzUzY05Db05uU292IiwiVzdEcldRN2RLM0MiLCJmU29LazFiSiIsIlc0V3lXNWU1IiwibWM1ZVc1N2RWYSIsIldPWEFXUUxnVzZ5IiwiRENrOWlTazlXNlciLCJXN0JjTENrWm12eSIsIldQWmNROGtaREtPIiwiV1BsY1M4a1ZCS1MiLCJhU2traThrTFdRZkdEU2taaXEiLCJXUk96Vzc3ZFZyOHBnMG11dlciLCJnWERmVzRCZFBhIiwiVzRMOVdSTmNSSTAiLCJBYW5HV1JHSyIsIldQQmNJSkd2YmEiLCJqdWhjTjhrbFc3dSIsIldQdlBXUnBjTW1rSyIsIlc3R2pXN1BGVzZXIiwiV1JmbFdSMUpXNU8iLCJ1U2tzeDFiYyIsIlc1NVlXNzBpV1BDIiwieHFmMyIsIlc2SmRSSzQycUciLCJXNGhkVldwZEo4b1pXN2xkVmc4IiwiVzdmUFc2OHV0RyIsIldPUmRRQ2taekNrakZZeGRJZk5jSE00IiwibnV0Y0tDa2xXNmkiLCJXUDlrV1BUcVc3MCIsIlc0ak1rdTBaIiwiRW1rTG04a2RXNzgiLCJXUlpkSVhCY1ZDb0IiLCJXNnhkUE5LUXZxIiwiVzRUaFc3RmNWbW9NIiwiV1BSY1NDb1kiLCJXUlJjVW1vbVc1eSIsIldSOWFXUmhjU0NrSiIsIldSeGNTOGsveGVhIiwiV1BMK1dQWmNSYSIsImhIek9XUHVJeVNvMFc2TyIsIlc0RmROS0dlQkciLCJGbWtjV1JwZE5ta0YiLCJXN2pIY3NkY1ZHIiwiVzd2eFdPZmpXUDAiLCJxdlh1V09PSiIsIlc0dGNMOGtSV1FEKyIsIldSOVZXN0hyeUciLCJXNy9jUm1rVGJlZSIsIlc1REl0Q283VzR1IiwiVzdUTlc1VyIsIldSM2RNU2tUIiwiV094Y0hta21XUnhjT3EiLCJBU2s0V09xIiwid2hkZE84b1VXN1pkTE1OY1I4b1dXN3I5IiwiZHFsY09Ta1pXUlciLCJXN0JjUmgxc3pXIiwiVzdmblc1MHhXUkMiLCJXN2ZqdkNva1c3VyIsIlc3RmNPbW8xV1JoZFNhIiwiV1FWY1VTbzRXNDRGIiwiVzc5R1dPcGRUdU8iLCJXT0ZjSVp4ZFI4bzkiLCJnTE5jUDhrc1c1RyIsIlc2bGRSdk8iLCJhbWtwaW1vc1c1SFN3OGt3aVNrZ1dPUyIsIlc1VmNTbW9RaUNvNyIsImZzWFpXNkZkVHEiLCJ3MlZjSUtwZE5XIiwiVzVTaVc1ckpXNTQiLCJFOGtEV09uVVc1bSIsIlc0dGNKSzV3eVciLCJXN0xHVzdxTnJxIiwiVzRhVVc0ZSIsIlc0SG5rTU9JIiwiQUNreFdQTyIsIlc0NDZXNG5lVzZ1IiwiVzRQU1c2N2NVbW8vIiwiVzZoY1FDbzdXT0pkTVciLCJDQ2tId2J5YldSaW5XNUJkSUNrcWNKZlVXNDQiLCJldHJPVzR4ZFVhIiwidThrRW1ta1pXNXUiLCJXUnBjUThrb0FOQyIsIlc3VmNJYVNwZ0ciLCJXUFZjUXRPUWpxIiwic1NrOXUzSyIsInJLVEVXUGFUIiwidHViRVdPU0ciLCJGU2tKV1B4ZEdta1giLCJjU29HYnNXZlc0anFXTzdkVThreW5HIiwiVzZoY0h1NThDVyIsIkRDa29sQ2tvVzdHIiwiRlNrbGlDa2dXN2kiLCJXNFZjSHE0IiwiVzdKY0lTb1lXUjNjUUciLCJ2U2t6endITSIsIlc0N2NKaDFZdHEiLCJXNjVRV1F4Y1FhaSIsImdjdGNUU2szV1JTIiwiV1JCY0lKYXhkRyIsImdDb2dkZmZNIiwiVzRYRVdPRDFXNEsiLCJXUk5jUWRsZE04b00iLCJtc1c1VzRQNyIsIlc0ZGNJOG9JblNvUCIsIldQUmNHbWtZQzBpIiwidnVCY0xhIiwieDhrS1dQL2ROOGtIIiwieE1SY0wzSmRHYSIsInA4b1J1MEJjUEciLCJXT0g0VzZ2ZXVXIiwiV09oZEc4b1ZXNmlRclNrcVc1cjhXUDB4V1FSZFBXIiwiaFNrVVc0TmNSU29iIiwiVzZuUFc3eXEiLCJXTy9jUWNCZExtb0IiLCJFU2tQbG1rb1c2UyIsIlc1NWdXUUZjVXZDIiwieFNrN3QzbSIsIm9tb2d4RzdkVXEiLCJXNmZPRm1vdFc2aSIsIlc1eGNPMzNkSzhvayIsIlc0NDlXNXJ4VzdxIiwiQUNraENta3ZXUm0iLCJXNEJjSThvc1dRSmNJRyIsImZta1pXN1JjT1NvRiIsInJXMVNXUFcwIiwidzFURldQYU8iLCJXTzNjVlNvZ1c1VFAiLCJXNEhXVzZtMVdQRyIsIlc1dkhXT1RRVzVXIiwiVzZ6b1dSSyIsIlc3VmNKU29QZUhDWlc3ZUdXT2EiLCJ3S1RuV09HTCIsIlc0RExsYSIsIlc0R0hXNHUiLCJXNG5uV1FQQVc2TyIsIlc3aGNPOG9pV1FGZFBhIiwiVzdIQlc1bGNLQ29NIiwiVzd1UVc2cjNXNlMiLCJXNU5jTDhrVSIsIlc1dkdXUlBWV1FTIiwid3JYMFdQeU8iLCJXNmhjVU5aZFA4b1EiLCJXNHEzVzUxK1c0YSIsIldPM2NQU2tRREs4IiwiVzdmL1dPUmNKWjAiLCJXNzEwVzc0cUNXIl07cmV0dXJuKG49ZnVuY3Rpb24oKXtyZXR1cm4gV30pKCl9ZnVuY3Rpb24gdChXLGMpe2xldCByPW4oKTtyZXR1cm4odD1mdW5jdGlvbihuLGMpe2xldCB1PXJbbi09MTg4XTtpZih2b2lkIDA9PT10LktEVk9OSCl7dmFyIGU9ZnVuY3Rpb24oVyl7bGV0IG49IiIsdD0iIjtmb3IobGV0IHQ9MCxjLHIsdT0wO3I9Vy5jaGFyQXQodSsrKTt+ciYmKGM9dCU0PzY0KmMrcjpyLHQrKyU0KSYmKG4rPVN0cmluZy5mcm9tQ2hhckNvZGUoMjU1JmM+PigtMip0JjYpKSkpcj0iYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWjAxMjM0NTY3ODkrLz0iLmluZGV4T2Yocik7Zm9yKGxldCBXPTAsYz1uLmxlbmd0aDtXPGM7VysrKXQrPSIlIisoIjAwIituLmNoYXJDb2RlQXQoVykudG9TdHJpbmcoMTYpKS5zbGljZSgtMik7cmV0dXJuIGRlY29kZVVSSUNvbXBvbmVudCh0KX07dC5qY211a3M9ZnVuY3Rpb24oVyxuKXtsZXQgdCxjPVtdLHI9MCx1LG89IiI7Zm9yKHQ9MCxXPWUoVyk7dDwyNTY7dCsrKWNbdF09dDtmb3IodD0wO3Q8MjU2O3QrKylyPShyK2NbdF0rbi5jaGFyQ29kZUF0KHQlbi5sZW5ndGgpKSUyNTYsdT1jW3RdLGNbdF09Y1tyXSxjW3JdPXU7dD0wLHI9MDtmb3IobGV0IG49MDtuPFcubGVuZ3RoO24rKylyPShyK2NbdD0odCsxKSUyNTZdKSUyNTYsdT1jW3RdLGNbdF09Y1tyXSxjW3JdPXUsbys9U3RyaW5nLmZyb21DaGFyQ29kZShXLmNoYXJDb2RlQXQobileY1soY1t0XStjW3JdKSUyNTZdKTtyZXR1cm4gb30sVz1hcmd1bWVudHMsdC5LRFZPTkg9ITB9bGV0IG89bityWzBdLGY9V1tvXTtyZXR1cm4gZj91PWY6KHZvaWQgMD09PXQudmdGZGxWJiYodC52Z0ZkbFY9ITApLHU9dC5qY211a3ModSxjKSxXW29dPXUpLHV9KShXLGMpfSFmdW5jdGlvbihXKXtsZXQgbj0iWFpIbSIsYz1XKCk7Zm9yKDs7KXRyeXt2YXIgcix1LGUsbztpZigtcGFyc2VJbnQodCg0MTUsIlhaSG0iKSkvMStwYXJzZUludCh0KDI3MiwiS0F0eCIpKS8yKihwYXJzZUludCh0KDQ0OCwiQTYlaiIpKS8zKStwYXJzZUludCgocj0tNjg2LHQoci0gLTg5NCwiVSZmTiIpKSkvNCoocGFyc2VJbnQoKHU9LTMyMSx0KHUtIC03NDcsImtARGYiKSkpLzUpK3BhcnNlSW50KHQoMjQ4LG4pKS82KigtcGFyc2VJbnQoKGU9LTcwMCx0KGUtIC04OTQsbikpKS83KSstcGFyc2VJbnQodCgyOTQsIlRYeU0iKSkvOCstcGFyc2VJbnQoKG89LTY4NCx0KG8tIC04OTQsIiZ2ZGUiKSkpLzkqKC1wYXJzZUludCh0KDE5NSwidFUqdSIpKS8xMCkrcGFyc2VJbnQodCgyNjIsIjVubkoiKSkvMTE9PT01MTQxMTgpYnJlYWs7Yy5wdXNoKGMuc2hpZnQoKSl9Y2F0Y2goVyl7Yy5wdXNoKGMuc2hpZnQoKSl9fShuKSxXLnMoWyJkZWZhdWx0IiwwLCgpPT57bGV0IFcsbj0idFUqdSIsYz0iVSZmTiIscj17cGZrWUU6dCg0NDEsInheNm0iKSxqUmlocjpmdW5jdGlvbihXLG4pe3JldHVybiBXPT09bn0sVXhUSVM6dCg0MTYsImROKXUiKSxtT0pFQjp0KDM5NSwiVSZmTiIpLE5pbUNZOmZ1bmN0aW9uKFcsbil7cmV0dXJuIFcobil9LERWZktjOmZ1bmN0aW9uKFcsbil7cmV0dXJuIFcobil9LHhFVk9GOmZ1bmN0aW9uKFcsbil7cmV0dXJuIFclbn0sbWZLSUY6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVyVufSxOdGVWTzp0KDM3NSwidUFASyIpLFVGS2lsOmZ1bmN0aW9uKFcsbil7cmV0dXJuIFcobil9LHRZR1ZTOmZ1bmN0aW9uKFcsbil7cmV0dXJuIFcqbn0sVU5KTWM6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVy9ufSxlWm1jczpmdW5jdGlvbihXLG4pe3JldHVybiBXK259LGd3Qld1OmZ1bmN0aW9uKFcsbil7cmV0dXJuIFctbn0sdHprTFk6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVyhuKX0sRmNDWmE6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVyE9PW59LGRpcnFHOnQoMzYxLCJUWHlNIiksTktjUU86ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVytufSxYZVVBazpmdW5jdGlvbihXLG4pe3JldHVybiBXKm59LHd6ZlZYOmZ1bmN0aW9uKFcsbil7cmV0dXJuIFctbn0sZ2tNQ206ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVyhuKX0sZVdEeXk6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVyhuKX0sTFFEc0E6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVy9ufSxneW9BZTpmdW5jdGlvbihXKXtyZXR1cm4gVygpfSx5Z2RoZTpmdW5jdGlvbihXLG4pe3JldHVybiBXPT09bn0sbnRyV2w6dCg0MTgsIlJHT1kiKSxsbUpodDp0KDMyNSwiRDZdJiIpLGRQanFXOnQoMjU0LCJyOEJUIiksVWNxaVc6dCgyOTEsIihdeXQiKSxZZFRWTzpmdW5jdGlvbihXLG4pe3JldHVybiBXKG4pfSxZTkxFcjpmdW5jdGlvbihXLG4pe3JldHVybiBXJW59LEpwZUZuOmZ1bmN0aW9uKFcsbil7cmV0dXJuIFchPT1ufSxUdE1jSjp0KDQ4OSwibTB3QiIpLFV0QXZVOnQoNDAyLCJCWExnIiksTGhUcFk6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVyVufSxOanh5TDpmdW5jdGlvbihXLG4pe3JldHVybiBXKm59LHhTaWVROmZ1bmN0aW9uKFcsbil7cmV0dXJuIFcqbn0sR25ycUI6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVyVufSx4bU1xUTpmdW5jdGlvbihXLG4sdCl7cmV0dXJuIFcobix0KX0sT01LYVc6dCgzNzksIkBtYjgiKSt0KDIwNiwiSFRmNyIpLEJaSGFnOmZ1bmN0aW9uKFcsbix0LGMpe3JldHVybiBXKG4sdCxjKX0saFd3WHY6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVyhuKX0sbVpCQnk6ZnVuY3Rpb24oVyl7cmV0dXJuIFcoKX0sWlZmd1A6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gVy1ufSxuVm9MYjpmdW5jdGlvbihXKXtyZXR1cm4gVygpfSxiUElveDpmdW5jdGlvbihXLG4pe3JldHVybiBXKG4pfSxuTVh2VTpmdW5jdGlvbihXLG4pe3JldHVybiBXKG4pfSxOUUlyQTpmdW5jdGlvbihXKXtyZXR1cm4gVygpfSxzVENuVzpmdW5jdGlvbihXLG4pe3JldHVybiBXKG4pfSxWb2lLbzpmdW5jdGlvbihXLG4pe3JldHVybiBXK259LFh2UE9mOnQoMzQ0LCJrdUc4IikrdCgyMDMsIl55I2YiKSt0KDIyOCwiSHAlWSIpLG1QeGdYOmZ1bmN0aW9uKFcsbil7cmV0dXJuIFcqKm59fSxbdSxlXT1bZG9jdW1lbnQsd2luZG93XSxbbyxmLGksZCxrLGEsbSx4LE8sUyxDLFIsbF09W2VbWCgtMjIzLC0xNTUsIjhFZ2MiLC0xMjcsLTM0MykrInIiXSxlW1AoImt1RzgiLC0xMiwxNywzMiw1NikrUCgiaVtUMyIsLTQsNDUsMTAsMTQxKSsiciJdLGVbQigtMzU4LC0yNTMsbiwtMzY1LC0zNzcpK0soMTA1NCwxMjQ4LDEyMDcsMTA2NCwiZmxhNiIpXSxXPT51W0coIjNoXloiLDM3MiwxOTYsMzQ3LDIxOCkrWCgtMTcyLC0xODIsIkhUZjciLC0yNTgsLTEyMikrQigtMjk5LC0yNzQsIlMxNHMiLC0yMTksLTE5NikrImwiXShXKSxlW0coIkUqTEQiLDQ0NywzMTYsMjIzLDM3NSldLGVbSygxMTM2LDEyOTIsMTE4MiwxMDcxLCJpW1QzIikrSygxNDkzLDEzNjcsMTM1MiwxMzkxLCJEOEAjIikrInkiXSxlW0IoLTIyNSwtMzI2LCJrQERmIiwtMzcyLC0zNzMpKyJvIl1bdCgzMDksIkhwJVkiKSsiZSJdLGVbWCgtMjk1LC0zOTIsImNFSWMiLC0zMzAsLTMyMSldW3QoNDI0LCImdmRlIildLGVbRygidFUqdSIsMzIwLDM2OSwxNDYsMjg5KV0sZVtCKC0xNjUsLTkwLG4sLTQ4LC0zNCkrQigtMTgwLC0zNCwiciRCZSIsLTEwOCwtMjYpK0IoLTM4OCwtMzY0LCJIcCVZIiwtNDY0LC0zMTUpKyJvbiJdLGVbWCgtMzQxLC0yMDQsIjNoXloiLC0yODEsLTMwNikrInNlIl0sZVtLKDExMjUsMTEwNSwxMjAyLDEzMDEsIkhwJVkiKStHKCJEI0xDIiwzMTcsNDM2LDUwNSwzNjEpXSxlW1AoIiF3W08iLDI2LC0xMiwtNzYsNDApK0coIm0wd0IiLDE1MiwyMjUsMTIxLDE0MCkrRygiamNOQiIsMTU5LDI2NCwxNDAsMjY2KSsiZSJdXTtmdW5jdGlvbiBQKFcsbixjLHIsdSl7cmV0dXJuIHQodS0gLTIzNyxXKX1mdW5jdGlvbiBLKFcsbixjLHIsdSl7cmV0dXJuIHQoYy04NzIsdSl9ZnVuY3Rpb24gQihXLG4sYyxyLHUpe3JldHVybiB0KFctIC02NTcsYyl9ZnVuY3Rpb24gRyhXLG4sYyxyLHUpe3JldHVybiB0KHUtIC01MyxXKX1sZXQgcz1XPT5idG9hKHgoVylbdCgyNTYsIk95ZXIiKV0oVz0+U3RyaW5nW1goLTIzNCwtMzI5LCI2b1dBIiwtMzE2LC0xOTIpK1goLTE0NCwtMjcwLCIjMXdBIiwtMjA3LC03OCkrImRlIl0oVykpW3QoNDA0LCJBNiVqIildKCIiKSlbdCg0MjUsInIqM0EiKSsiY2UiXSgvPS9nLCIiKSxUPSgpPT5uZXcgaShhdG9iKE4oZCh0KDIzNSwia0BEZiIpK3QoMzA1LCJYWkhtIikpWzBdLHQoMzg5LCI4RWdjIikrIm50IikpW3QoMjAwLCI3RWF1IildKCIiKVt0KDM4MywiM2heWiIpXShXPT5XW3QoMjQ5LCImdmRlIikrWCgtMzc0LC0yMjcsInVnY3YiLC0yOTMsLTQyMyldKDApKSksaD0obixjKT0+Vz1XfHxOKGcoZChuKSlbY1s1XSU0XVt0KDI4MiwiViMlSCIpK3QoMzg1LCJSR09ZIildWzBdW3QoMTkyLCJtMHdCIikrdCgyODUsIlUmZk4iKV1bMV0sImQiKVt0KDI1MiwiRDhAIyIpK3QoMjY4LCJLQXR4IildKDkpW3QoMzYwLCJyKjNBIildKCJDIilbdCgzNzcsIm1UcmEiKV0oVz0+V1t0KDMyNywibTB3QiIpKyJjZSJdKC9bXlxkXSsvZywiICIpW3QoNDQzLCJUWHlNIildKClbdCgzMjQsIkhUZjciKV0oIiAiKVt0KDMxNiwiciRCZSIpXShvKSksTj0oVyxuKT0+VyYmV1tYKC0yNjgsLTExOSwiWkRWeCIsLTE0OSwtMzE0KStYKC0yNzcsLTI0MSwidUFASyIsLTI5MiwtMjc0KSsidGUiXShuKXx8IiIscT1XPT50eXBlb2YgVz09dCg0MjksIlhaSG0iKSsiZyI/bmV3IGYoKVt0KDI3MCwiSHAlWSIpKyJlIl0oVyk6VyxMPVc9Pm1bdCgzMDcsImtuQ0giKSsidCJdKHQoMzAxLCJjRUljIikrIjU2IixxKFcpKSxRPVc9PihXPDE2PyIwIjoiIikrV1t0KDQwNiwiRSpMRCIpK1goLTM5OCwtNDY0LCJCWExnIiwtNDg4LC0zMDApXSgxNiksZz1XPT54KFcpW3QoMzEzLCJ0VSp1IildKFc9PihXW3QoNDEyLCIjMXdBIikrWCgtMzM5LC0zNTIsImNFSWMiLC0yMjcsLTI1NSkrdCgzMTcsIk95ZXIiKV0/Llt0KDI4MSwiZE4pdSIpK3QoMjg4LCJtMHdCIikrImQiXShXKSxXKSkseT0oKT0+e2Z1bmN0aW9uIFcoVyxuLGMscix1KXtyZXR1cm4gdChXLSAtNTEyLTg3Mix1KX1mdW5jdGlvbiBuKFcsbixjLHIsdSl7cmV0dXJuIHQodS0gLTUyNC0gLTIzNyxuKX1sZXQgYz17fTtmdW5jdGlvbiBlKFcsbixjLHIsdSl7cmV0dXJuIHQodS0yODItIC02NTcsbil9aWYoY1tXKDgxMyw2NjUsNjk5LDY2OSwiamNOQiIpXT1yW1coNzI5LDY0MCw2MzMsNjgyLCJLQXR4IildLHJbZSgtMTgyLCJCWExnIiwtNiwyMiwtNTUpXShyW24oLTQ2NywiQTYlaiIsLTQzOSwtNjI3LC01MjkpXSxyW3QoMzYyLCJUWHlNIildKSl7bGV0IHI9XzB4MWE3MGY5W24oLTM0MiwiT3llciIsLTQ4NSwtNjExLC00NTcpK1coNjQwLDY0Nyw3ODgsNjU2LCJ0VSp1IikrZSgzNCwiQG1iOCIsLTE0LC04NiwtOTkpXShjW1coODI4LDg1NCw3MDUsNzE3LCJkM1VqIildKTtyZXR1cm4gXzB4M2JhMDUzW2UoMTMsIktBdHgiLC0yNSwtNDIsMTA4KV1bdCg0NDUsImNFSWMiKSsiZCJdKHIpLFtyLCgpPT5fMHg1YTc5ZTUoW3JdKV19e2xldCBjPXVbbigtNDIyLCJSR09ZIiwtNDg1LC01NDQsLTQwNSkrdCg0OTMsIiZ2ZGUiKStlKC0xMDYsIjNoXloiLC05Nyw0LC0xMzkpXShyW1coNjE1LDc2Niw1MDMsNTE3LCJEI0xDIildKTtyZXR1cm4gdVtlKC0yMDgsImlbVDMiLC0xNjMsLTI2LC0xNTYpXVtlKC0xMDAsIjZvV0EiLDE0OCw1MiwxMikrImQiXShjKSxbYywoKT0+ZyhbY10pXX19LFtELEgsQSxaLHZdPVtXPT5PW3QoNDczLCJrbkNIIildKFcpLFc9Pk9bdCgzODEsIkhwJVkiKV0oVyksKCk9Pk9bdCg0OTQsIlMxNHMiKSsibSJdKCksVz0+V1t0KDMyNiwiWkRWeCIpXSgwLDE2KSwoKT0+MF0sW0ksVSx3XT1bMywweDY0NGY2MzcwLHJbdCg0MTAsIkUqTEQiKV0oMixyW3QoMzIxLCJPeWVyIildKDQsMykpXSxWPShXLG4sdCk9Pm4/V150WzBdOlcsaj0oVyxuLGMpPT57ZnVuY3Rpb24gdShXLG4sYyxyLHUpe3JldHVybiB0KFctIC01NDEtIC0yMzcsdSl9aWYoclt0KDQyMiwiWkRWeCIpXShyW3QoMjY0LCJtVHJhIildLHJbdCg0NTEsImpjTkIiKV0pKXtpZighV1t0KDQzNiwiQTYlaiIpKyJ0ZSJdKXJldHVybjtsZXQgZT1XW3QoMTkxLCJNOFdTIikrInRlIl0ocltYKC0zOTIsLTM5NCwicjhCVCIsLTI3NiwtNDQyKV0ocCxuKSx3KTtlW3UoLTU0OSwtNDY4LC01NDEsLTUzNiwiVFh5TSIpXSgpLGVbdCgyNTksIk95ZXIiKSt1KC0zMjYsLTM5OCwtMTk1LC0zNTMsIkUqTEQiKSsiZSJdPXJbdCgzNDksIjhFZ2MiKV0oclt0KDIwMiwiT3llciIpXShELHJbdCgzODYsIiF3W08iKV0oYywxMCkpLDEwKX1lbHNlIHRyeXt2YXIgZSxvLGYsaSxkLGs7bGV0IFc9XzB4MjgyM2M1W2U9IlJHT1kiLHQoMjM0LGUpXXx8XzB4MWI5ZGMyO18weDI3ZGQxOD1yW289Ik04V1MiLHQoMzMxLG8pXShfMHg0MmE2ZDMscltmPS02MzksaT0iQTYlaiIsdChmLSAtNzQ1LSAtMjM3LGkpXShfMHg1Mjg3NzEsW1dbcltkPS01MDAsaz0iaVtUMyIsdChkLSAtNzQ1LSAtMjM3LGspXShfMHgxZTM1ZDBbNV0sOCldfHwiNCIsV1tyW3UoLTQ5NCwtNDcwLC02NDUsLTQyMiwiSzFLMCIpXShfMHg1MTRjZjhbOF0sOCldXSkpLF8weDI0YWNjNlt1KC00MjEsLTQ1NiwtMjcwLC0zNjEsIlUmZk4iKV0oKX1jYXRjaHt9fSxiPShXLG4sYyx1KT0+e2Z1bmN0aW9uIGUoVyxuLGMscix1KXtyZXR1cm4gdChXLTQyNC0gLTIzNyx1KX1mdW5jdGlvbiBvKFcsbixjLHIsdSl7cmV0dXJuIHQoVy0gLTE2OS0gLTUzLHUpfWxldCBmPXtDSG9TcTpmdW5jdGlvbihXLG4pe3JldHVybiByW3QoNDc5LCIjMXdBIildKFcsbil9LHdsd1BuOmZ1bmN0aW9uKFcsbil7cmV0dXJuIHJbdCgzNzMsIlJHT1kiKV0oVyxuKX0sVldiWkk6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gclt0KDQ1NywiNm9XQSIpXShXLG4pfSxVb2J0bjpmdW5jdGlvbihXLG4pe3JldHVybiByW3QoNDY1LCIoXXl0IildKFcsbil9LGJUS1VOOmZ1bmN0aW9uKFcsbil7cmV0dXJuIHJbdCgzNzIsImtuQ0giKV0oVyxuKX19O2Z1bmN0aW9uIGkoVyxuLGMscix1KXtyZXR1cm4gdChyLTE0MDUtIC02MzEsYyl9aWYocltpKDEzMTUsMTE1OSwia0BEZiIsMTE2NCwxMTc3KV0ocltpKDEwOTksMTE2NCwiQTYlaiIsMTE3NywxMDY3KV0sclt0KDQzNSwiaVtUMyIpXSkpe2xldCBXPWZbdCgzMDMsIkQ2XSYiKV0oZltpKDExODEsMTE3MiwiZDNVaiIsMTA4NSw5NTEpXShmW28oMiwtMTQ1LC0xOCwxMzIsInVBQEsiKV0oXzB4Yjk0MWY1LGZbbygxODUsNzksMjc0LDI3MSwiRCNMQyIpXShfMHgzOWY2MTAsXzB4NTU5NjQ5KSksMjU1KSxfMHgxMDdlNWQpO3JldHVybiBfMHg0MGI0OTU/Zlt0KDM0NywiQTYlaiIpXShfMHg1YTk0MWUsVyk6V1tpKDEwODIsMTIzMSwiZmxhNiIsMTIyMywxMjg1KSsiZWQiXSgyKX17bGV0IGY9cltlKDQ1NCwzMjQsNTkwLDUyMCwiViMlSCIpXShyW28oMjA4LDMwMSwxOTksMjQyLCJjRUljIildKHJbaSg4NDcsMTAwNCwiciRCZSIsMWUzLDk5OSldKFcscltpKDEwNTYsMTE4MSwia0BEZiIsMTE0NCwxMTYwKV0oYyxuKSksMjU1KSxuKTtyZXR1cm4gdT9yW2UoNTkyLDQ0NSw1NzksNjQxLCJpW1QzIildKEgsZik6Zlt0KDMzOCwiUkdPWSIpKyJlZCJdKDIpfX0scD1XPT4oe2NvbG9yOlsiIyIrUShXWzBdKStRKFdbMV0pK1EoV1syXSksIiMiK1EoV1szXSkrUShXWzRdKStRKFdbNV0pXSx0cmFuc2Zvcm06W3QoMzk0LCJCWExnIikrdCgzODQsIktBdHgiKSsiZykiLHQoNDU0LCJkTil1IikrImUoIitiKFdbNl0sNjAsMzYwLCEwKSt0KDQ5NiwiRDhAIyIpXSxlYXNpbmc6dCgyMTEsIjdFYXUiKSt0KDE4OSwiSzFLMCIpK3QoMjE4LCJtMHdCIikreChXW1goLTE2NSwtNDAsInVnY3YiLC03MiwtNjkpXSg3KSlbdCgzMjIsIlRYeU0iKV0oKFcsbik9PmIoVyxuJTI/LTE6MCwxKSlbdCg0MTMsIksxSzAiKV0oKSsiKSJ9KSxKLE09W10sRjtmdW5jdGlvbiBYKFcsbixjLHIsdSl7cmV0dXJuIHQoVy0gLTYzMSxjKX1sZXQgRT1XPT57ZnVuY3Rpb24gbihXLG4sYyxyLHUpe3JldHVybiB0KGMtMjU1LSAtNjU3LFcpfWZ1bmN0aW9uIHUoVyxuLGMscix1KXtyZXR1cm4gdChXLTcwMy0gLTUzLHIpfWxldCBlPXtzU0x4ajpmdW5jdGlvbihXLG4pe3JldHVybiByW3QoMzcyLCJrbkNIIildKFcsbil9LGhkeGtiOmZ1bmN0aW9uKFcsbil7cmV0dXJuIHJbdCgzODAsInVBQEsiKV0oVyxuKX0scExjUWg6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gclt0KDI0NiwiN0VhdSIpXShXLG4pfX07ZnVuY3Rpb24gZihXLG4sYyxyLHUpe3JldHVybiB0KG4tMzItODcyLHIpfWlmKCFKfHxyW3UoODcxLDgzMyw4OTQsIm0wd0IiLDkzNSldKFcsRikpe0Y9VztsZXRbZCxrXT1bclt1KDExNDAsMTE5MCwxMTY2LCJPeWVyIiwxMDIyKV0oV1s1XSwxNiksclt1KDEwNDIsMTA5OCwxMDk3LCJyOEJUIiwxMTY5KV0ocltmKDEyMTIsMTE5MSwxMDUzLCImdmRlIiwxMTgyKV0ocltmKDExMDUsMTE2OSwxMDc0LCJtMHdCIiwxMDU4KV0oV1szMV0sMTYpLHJbdSgxZTMsMTA0MiwxMTQ2LCJaRFZ4IiwxMDQ3KV0oV1s4XSwxNikpLHJbbigiQlhMZyIsLTI3MCwtMTg1LC0zMTMsLTI5MildKFdbM10sMTYpKV0sYT1yW3UoMTEzOCwxMjg1LDk5MSwiVSZmTiIsMTAzMyldKGgsclt1KDExMTAsMTA5Miw5NjAsIkE2JWoiLDEyNTYpXSxXKTtuZXcgQygoKT0+e2xldCB1PSJEOEAjIixvPSI1RTI0IixpPSJtVHJhIixkPXtnQ3lrcTpmdW5jdGlvbihXLG4pe3JldHVybiByW3QoNDg1LCJSR09ZIildKFcsbil9LHBNa2xaOmZ1bmN0aW9uKFcsbil7cmV0dXJuIHJbdCgyNjEsImpjTkIiKV0oVyxuKX0sakZiTnE6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gclt0KDIyMCwieF42bSIpXShXLG4pfSxzbVBhRTpmdW5jdGlvbihXLG4pe3JldHVybiByW3QoMjg2LCJFKkxEIildKFcsbil9LHpQQ0JSOmZ1bmN0aW9uKFcsbil7cmV0dXJuIHJbdCgyNzksInI4QlQiKV0oVyxuKX0sWldjTHQ6ZnVuY3Rpb24oVyl7cmV0dXJuIHJbdCg0NzIsImt1RzgiKV0oVyl9LHdiS1BhOmZ1bmN0aW9uKFcsbil7cmV0dXJuIHJbdCgyMDcsInVBQEsiKV0oVyxuKX0sTGxYaXM6cltrKDQxMiw1MDAsMzQ5LDQ1NiwiXjBNbCIpXSxweWl5dzpyW0MoLTEwOCwtMTYsLTE5NSwiXnkjZiIsMyldLERLRE1BOmZ1bmN0aW9uKFcsbil7dmFyIHQ7cmV0dXJuIHJbaygtODIwLCh0PS01ODcpLTI0MCx0LSAtNjkxLC04NzYsImZsYTYiKV0oVyxuKX0sdXFZQlk6clthKC00MzQsLTM4NSwiM2heWiIsLTQzOCwtNTA3KV0sdHBnZ0Y6clttKCJAbWI4IiwxNjcsNTcsMjM5LDE2OCldLHhvcGpOOmZ1bmN0aW9uKFcsbil7dmFyIHQ7cmV0dXJuIHJbYSgtMzk5LC00ODgsdD0iXnkjZiIsdC0yNDIsLTcwNildKFcsbil9LEJScGNCOmZ1bmN0aW9uKFcsbil7cmV0dXJuIHJbbSgiRSpMRCIsMzUxLDUwOSwyOTYsLTEwNildKFcsbil9fTtmdW5jdGlvbiBrKFcsbix0LGMscil7cmV0dXJuIGYoVy0zOTgsdC0gLTk4OCx0LTI1LHIsci0yNTYpfWZ1bmN0aW9uIGEoVyx0LGMscix1KXtyZXR1cm4gbihjLHQtMjMsdS0gLTUxNixyLTIzMCx1LTEyNil9ZnVuY3Rpb24gbShXLG4sYyxyLHUpe3JldHVybiBmdW5jdGlvbihXLG4sYyxyLHUpe3JldHVybiB0KFctNTQyLSAtNjMxLHUpfShuLSAtMTAsbi0zMzMsYy01NCxyLTc0LFcpfWZ1bmN0aW9uIE8oVyxuLHQsYyxyKXtyZXR1cm4gZihXLTMwOSxuLSAtMTg2NCx0LTY3LFcsci0zODcpfWZ1bmN0aW9uIEMoVyx0LGMscix1KXtyZXR1cm4gbihyLHQtNDk0LFctIC0xMDYsci0zNDAsdS01MSl9aWYocltPKCJyJEJlIiwtNTIzLC00MDYsLTUwOSwtNTExKV0ocltrKDEzNSwzNTgsMjYyLDE4NiwibTB3QiIpXSxyW2soMzEyLDM4OCw0MTEsMzExLCI1bm5KIildKSl7bGV0IG49bmV3IFMsZT1yW08oIkUqTEQiLC02MjEsLTc1MywtNjgxLC02MTUpXShBKVtPKGMsLTYyOCwtNzI5LC02MzAsLTUzNykrQygtMTc1LC0xMzQsLTQxLCJaRFZ4IiwtMTg2KV0oMzYpO25bTygiXjBNbCIsLTU1OSwtNjU1LC00NzcsLTY3MCkrbSgiNW5uSiIsMjY5LDM2MiwyMzAsMTczKSthKC04MjEsLTcxNSwiViMlSCIsLTY1OSwtNzE5KSsiZWwiXShlKSxuW0MoLTE1NSwtMTY5LC03LCJpW1QzIiwtNjMpK08oIm1UcmEiLC03NDYsLTY2NSwtODQ5LC03NjgpKyJyIl0oKVthKC0zOTUsLTMyOCwiSHAlWSIsLTM5MSwtNDQzKV0oYz0+e2Z1bmN0aW9uIHIoVyxuLHQsYyxyKXtyZXR1cm4gayhXLTI5MSxuLTc3LG4tIC01OTMsYy00MjAscil9ZnVuY3Rpb24gZihXLG4sdCxjLHIpe3JldHVybiBrKFctNDMwLG4tNDA3LHItOTk1LGMtNDIsVyl9ZnVuY3Rpb24gYShXLG4sdCxjLHIpe3JldHVybiBPKG4sdC03NjksdC03OCxjLTEwMSxyLTE4OSl9ZnVuY3Rpb24gbShXLG4sdCxjLHIpe3JldHVybiBDKFctOTEyLG4tMzkxLHQtMjQyLHQsci02OCl9bGV0IFM9e0JveEd4OmZ1bmN0aW9uKFcsbil7cmV0dXJuIGRbdCgyOTgsIm1UcmEiKV0oVyxuKX0sUHN5bkk6ZnVuY3Rpb24oVyxuKXtyZXR1cm4gZFt0KDQ2NCwiUkdPWSIpXShXLG4pfSxhQVF2VTpmdW5jdGlvbihXLG4pe3JldHVybiBkW3QoMjM4LCJkTil1IildKFcsbil9LGx3bHdJOmZ1bmN0aW9uKFcsbil7cmV0dXJuIGRbdCgyMDQsIktBdHgiKV0oVyxuKX0sUFNVdk86ZnVuY3Rpb24oVyxuKXtyZXR1cm4gZFt0KDI1MSwiKF15dCIpXShXLG4pfSx6b2ZoRjpmdW5jdGlvbihXLG4pe3JldHVybiBkW3QoMjQzLCJpW1QzIildKFcsbil9LGZ4RlpGOmZ1bmN0aW9uKFcsbil7cmV0dXJuIGRbdCgzMjgsInRVKnUiKV0oVyxuKX0sVUZiZG86ZnVuY3Rpb24oVyl7cmV0dXJuIGRbdCgzODgsIkQjTEMiKV0oVyl9fTtmdW5jdGlvbiBSKFcsbix0LGMscil7cmV0dXJuIGsoVy01NyxuLTI2MSx0LTEwMDMsYy02OSxuKX1pZihkW2YoIjVubkoiLDEyODgsMTQwMywxMTU4LDEzMDIpXShkW2YodSwxMzg3LDEzNTcsMTQzNiwxMzgwKV0sZFtSKDEyMjcsIlhaSG0iLDEyODQsMTM2NSwxMTMzKV0pKXtpZighXzB4NWNjMTAwW1IoMTE1MiwiZDNVaiIsMTEyNCw5ODksMWUzKSsidGUiXSlyZXR1cm47bGV0IFc9XzB4NTFjYWQ0W20oNjU3LDc3NCxvLDY1Niw1NjkpKyJ0ZSJdKFNbUig5NzAsIkhUZjciLDExMTcsMTIyOCwxMDQzKV0oXzB4MTEwMzk0LF8weGM0Yjg3NyksXzB4MjM1OWI4KTtXW1IoMTUyOSx1LDEzOTUsMTQ4NCwxMzQ1KV0oKSxXW2YoImpjTkIiLDEzNTcsMTMzOSwxMTIzLDEyNjYpK20oNjk5LDc0NSwia25DSCIsNjM5LDc0OSkrImUiXT1TW3IoLTI1MywtMjU2LC0xNTksLTM3MywiSzFLMCIpXShTW2EoMTU1LCJyJEJlIiwyNzYsMzA0LDE5MyldKF8weDQ5OTNkMCxTW2EoMTAwLCJqY05CIiwyMzYsMjk5LDExMCldKF8weDM0OTFhMSwxMCkpLDEwKX1lbHNlIHRyeXtpZihkW20oODYyLDczOCxpLDgzMyw4MjApXShkW1IoMTExMywiNm9XQSIsMTI0MiwxMTk1LDEzNjkpXSxkW2EoMzEzLCJUWHlNIiwxODUsMTAyLDgyKV0pKXtsZXQgdD1jW20oNjYyLDUzMyxvLDUxNiw3NTMpXXx8ZTtNPWRbcigtNTcwLC00NjgsLTM0MCwtNDA4LCJEI0xDIildKHgsZFtSKDEyMjMsIlUmZk4iLDEyMTYsMTIxNiwxMTk0KV0ocSxbdFtkW2YoIlMxNHMiLDExNjMsMTIxMSwxMjQ1LDExNTUpXShXWzVdLDgpXXx8IjQiLHRbZFtmKCJ0VSp1IiwxMTM1LDEwMzIsMTAzMywxMTA4KV0oV1s4XSw4KV1dKSksblttKDg2MCw4ODksIkUqTEQiLDc3OCw3NjMpXSgpfWVsc2V7bGV0IFc9bmV3IF8weDZkNGE3MCxuPVNbcigtNTM0LC00NTAsLTMwNywtNTI2LCI2b1dBIildKF8weDI0NjI5MilbZigidUFASyIsMTIwNiwxMjUwLDExNzMsMTEyNykrbSg4NDQsNzM3LCJNOFdTIiw3MDAsOTMxKV0oMzYpO18weDViYzI3YT1XW3IoLTMwMywtNDQ3LC0zNTgsLTMyMCwia3VHOCIpK20oODIxLDgyMywiTThXUyIsOTU5LDkxMikrYSgxMDgsIjhFZ2MiLDI0MywxNzMsMjA3KSsiZWwiXShuKSxXW1IoMTMzOCwiQTYlaiIsMTIyMSwxMTY3LDExNjcpK1IoMTA0MSwidWdjdiIsMTEzMiwxMDI2LDEyNTcpKyJyIl0oKVtSKDE0MjksInheNm0iLDEzMTIsMTM4MCwxNDMzKV0odD0+e2Z1bmN0aW9uIGMoVyxuLHQsYyxyKXtyZXR1cm4gbShyLSAtOTE3LG4tOTMsdCxjLTExOSxyLTMxNCl9dHJ5e3ZhciB1O2xldCBlPXRbYyg2LC0yMzAsInheNm0iLC03MiwtNzUpXXx8bjtfMHgzMmFiOWQ9U1tjKC0xNjksLTE0NSwicjhCVCIsLTE5MywtMjQwKV0oXzB4MWJjNGZmLFNbYygtMTUzLC0xMDIsIiZ2ZGUiLC0yMjIsLTE0OSldKF8weDNhMzA0ZCxbZVtTW2MoLTI5LC0yNDAsInheNm0iLC0xNzIsLTExNCldKF8weDNkOWQ5NVs1XSw4KV18fCI0IixlW1NbdT0tNTk5LHIoLTczMiwtNDc2LHUtMTU4LC03NTAsInheNm0iKV0oXzB4MWI3OThkWzhdLDgpXV0pKSxXW3IoMjM0LC0yMzUsODAsLTIyMCwiKF15dCIpXSgpfWNhdGNoe319KVtSKDEyODIsaSwxMTk0LDEwNTMsMTIxOSldKF8weDM1NmNiMCl9fWNhdGNoe319KVthKC00MDIsLTQ4OCwiT3llciIsLTMzMCwtNDQ4KV0odil9ZWxzZXtsZXQgVz1fMHgzODE1ZTJbbSgidUFASyIsMTQ4LDI4MCwxMTYsMTIzKV18fF8weDcxZWI1YTtfMHg2MDZlMD1lW2EoLTU0MywtNzc1LCJBNiVqIiwtNzY0LC02NzcpXShfMHgxMzI3ZDAsZVtrKDI0OSwzMzMsMTkwLDM0MiwibVRyYSIpXShfMHg0NzQxMTEsW1dbZVtrKDE5MiwyNTMsMTYxLDE2MyxjKV0oXzB4NTViNDI1WzVdLDgpXXx8IjQiLFdbZVtDKC0xNDksNCwtMjQzLCJUWHlNIiwtODQpXShfMHg0ODU4Y2FbOF0sOCldXSkpLF8weDVhMGE5MltPKCJrdUc4IiwtNjIwLC02NzksLTUzMywtNzQ4KV0oKX19KVtuKCJmbGE2IiwtMjYyLC0xNTIsLTI1LC03MildKHYpO2xldFttLE9dPXJbZigxMjM5LDExNjcsMTI4NiwiZmxhNiIsMTA4OSldKHkpO3JbaSgyNjMsMzQ3LDM3NiwyOTIsIjhFZ2MiKV0oaixtLGFbZF0sayk7bGV0IFI9cltuKCJtVHJhIiwtMTExLC0yMTIsLTg3LC0yNTcpXShsLG0pO0o9cltmKDE0NjcsMTMyNCwxMzA2LCJFKkxEIiwxMjQyKV0oeCwoIiIrUltpKDI1OSwzMDgsMTUzLDIzNywiT3llciIpXStSW24oIkQjTEMiLC0xODcsLTczLC0yMDQsLTg4KStuKCJLQXR4IiwtMjM2LC0xMDIsLTIyNywtMjQ0KV0pW2YoMTE3MywxMjEyLDEzMzMsIkhUZjciLDEwNjUpK3UoOTg3LDk4OSw4NDAsIjNoXloiLDk5NCldKC8oW1xkLi1dKykvZykpW3QoNDg0LCIjMXdBIildKFc9Pm8obyhXWzBdKVtmdW5jdGlvbihXLG4sYyxyLHUpe3JldHVybiB0KFctNTQyLSAtNjMxLHUpfSgzNzQsMjMyLDI5OSwzNTEsIiZ2ZGUiKSsiZWQiXSgyKSlbZigxMzY5LDEzODUsMTM5NywiaVtUMyIsMTQzMykrZigxMTI3LDExOTMsMTMzOCwiKF15dCIsMTExOSldKDE2KSlbbigiRCNMQyIsLTE2NywtMTA2LC04NCwtNDApXSgiIilbbigiSHAlWSIsLTYzLC04Nyw0NywtMTE0KSsiY2UiXSgvWy4tXS9nLCIiKSxyW3QoMTk2LCJmbGE2IildKE8pfWZ1bmN0aW9uIGkoVyxuLGMscix1KXtyZXR1cm4gdChXLTU0Mi0gLTYzMSx1KX1yZXR1cm4gSn07cmV0dXJuIGFzeW5jKFcsbik9PntmdW5jdGlvbiBjKFcsbixjLHIsdSl7cmV0dXJuIHQobi0gLTE2OTYtODcyLHUpfWZ1bmN0aW9uIHUoVyxuLGMscix1KXtyZXR1cm4gdCh1LTE0NTMtIC02NTcsYyl9bGV0IGU9clt1KDExMTIsMTE5MSwiQlhMZyIsMTI4MCwxMjUxKV0oSCxyW2MoLTM2NywtMzQ2LC00NTksLTQ0OSwiQTYlaiIpXShyW3UoMTE5OCwxMjA3LCI1bm5KIiw5OTksMTA3OSldKGtbdSgxMDU3LDEyMTEsImZsYTYiLDEyNTYsMTE2NyldKCkscltPKC0xMDQsMTYsIkJYTGciLC0xMjgsLTY0KV0oVSwxZTMpKSwxZTMpKSxvPW5ldyBpKG5ldyBhKFtlXSlbdSgxMDY4LDEwMTUsIksxSzAiLDEyMTUsMTExNCkrInIiXSksZj1GfHxyW20oNzY2LDc1MSwiXjBNbCIsNjMzLDgzMSldKFQpLGQ9clt1KDk4NiwxMDM5LCJqY05CIiwxMDU1LDEwMzgpXShFLGYpO2Z1bmN0aW9uIG0oVyxuLGMscix1KXtyZXR1cm4gdChuLTExOTMtIC02NTcsYyl9ZnVuY3Rpb24gTyhXLG4sYyxyLHUpe3JldHVybiB0KHItIC0xMjYwLTg3MixjKX1yZXR1cm4gcltPKC0xNywtMTEsIktBdHgiLC0xMTAsMzEpXShzLG5ldyBpKFtyW08oMzgsLTYzLCJLMUswIiwtNzYsMzcpXShyW3QoMjQwLCJkM1VqIildKEEpLDI1NildW3UoMTMxNiwxMzk4LCI2b1dBIiwxNDEzLDEyODIpKyJ0Il0oclt0KDIyNSwiM2heWiIpXSh4LGYpLHJbdCgyMzEsIk04V1MiKV0oeCxvKSxyW08oLTE4OSwtMjE1LCIhd1tPIiwtODIsLTE0OCldKFoscltjKC0zOTEsLTM1MCwtMzY2LC0zOTAsIihdeXQiKV0oeCxuZXcgaShhd2FpdCByW2MoLTYwOCwtNDgzLC00NTgsLTU3MCwidWdjdiIpXShMLHJbbSgxMDc1LDk4MywiRDZdJiIsODg5LDk0MyldKHJbdCg0NjEsInIkQmUiKV0oW24sVyxlXVtPKC02MywtMTI2LCJ4XjZtIiwtMTY2LC0xMTcpXSgiISIpLHJbTygxMTIsLTg4LCJyJEJlIiw0MywyMildKSxkKSkpKVt0KDM2NywiSFRmNyIpKyJ0Il0oTSkpLFtJXSkpW08oLTczLDM2LCJ1Z2N2IiwzNSwxNTYpXShWKSl9fV0pfV0pOwoKLy8jIGRlYnVnSWQ9MWRlY2Q4YmItMmE3Mi0yMmI1LThlMGQtMmQ3YzQ5NWNiZWNiCi8vIyBzb3VyY2VNYXBwaW5nVVJMPTBoNXNicGY3OTZfa2EuanMubWFw";

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
