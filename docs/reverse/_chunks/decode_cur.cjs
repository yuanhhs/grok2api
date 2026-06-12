// 自适配解码器:从 sig_cur.js 自身提取 W 解码器 + 字符串数组(自洽),
// 解码签名函数体内所有 W(idx,"key") 调用 -> 明文。适配任意 build。
const fs = require("fs");
const path = require("path");

const file = process.argv[2] || path.join(__dirname, "sig_cur.js");
const src = fs.readFileSync(file, "utf8");
const lines = src.split("\n");
// 签名逻辑在最长那一行
const L = lines.reduce((a, b) => (b.length > a.length ? b : a), "");

// 从 push(["object"==...,1645e3,n=>{ ... }]) 里抠出 module factory body
const modStart = L.indexOf("1645e3,n=>{");
if (modStart < 0) throw new Error("module 1645e3 anchor not found");
// W 函数定义 + t() 字符串数组 + 自检 IIFE 都在 module body 顶部。
// 直接 eval 整个 module body 的前缀(到 n.s(["default" 之前),拿到 W。
const bodyFrom = L.slice(modStart + "1645e3,".length); // n=>{...}
// 找到 factory 箭头函数体的 { ... }:从第一个 { 开始
const braceStart = bodyFrom.indexOf("{");
// 截到 n.s(["default" (签名注册)之前,这段含 W/t/自检
const defAnchor = bodyFrom.indexOf('n.s(["default"');
const prelude = bodyFrom.slice(braceStart + 1, defAnchor);

// 构造一个沙箱:prelude 定义了 function W 和 function t,自检 IIFE 会旋转数组。
// 注意自检 IIFE 内部可能依赖 W,执行它让数组旋转到正确位置。
const sandbox = `
${prelude}
module.exports = { W: W };
`;
const Module = require("module");
const m = new Module();
m._compile(sandbox, "sandbox_cur.cjs");
const W = m.exports.W;

// 现在解码签名函数体里所有 W(idx,"key")
const sigStart = L.indexOf('n.s(["default"');
const body = L.slice(sigStart);
console.log("[body] len", body.length);

const re = /W\((\d+),"((?:[^"\\]|\\.)*)"\)/g;
let mm, seen = new Set(), rows = [];
while ((mm = re.exec(body))) {
  const idx = +mm[1];
  const key = mm[2].replace(/\\(.)/g, "$1");
  const sig = idx + "|" + key;
  if (seen.has(sig)) continue;
  seen.add(sig);
  let val;
  try { val = W(idx, key); } catch (e) { val = "ERR:" + e.message; }
  rows.push([idx, key, val]);
}
console.log("[calls]", rows.length, "unique\n");
for (const [i, k, v] of rows) console.log(i, JSON.stringify(v));
