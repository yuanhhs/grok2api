const fs = require("fs");
const path = require("path");
const src = fs.readFileSync(path.join(__dirname, "sig_cur.js"), "utf8");
const L2 = src.split("\n")[1];

// 复用 decode_cur 的 W 提取逻辑
const mW = L2.match(/function W\(n,r\)\{[\s\S]*?return\(t=function\(\)\{return n\}\)\(\)\}/);
const selfCheck = L2.match(/!function\(n\)\{let t=n\(\);for\(;;\)try\{[\s\S]*?\}catch\(n\)\{t\.push\(t\.shift\(\)\)\}\}\(t\)/);
const code = mW[0] + ";" + selfCheck[0] + "; module.exports={W};";
const mod = { exports: {} };
new Function("module", code)(mod);
const W = mod.exports.W;

const start = L2.indexOf('n.s(["default"');
let body = L2.slice(start, start + 14000);
body = body.replace(/W\((\d+),"((?:[^"\\]|\\.)*)"\)/g, (m, idx, key) => {
  try { return JSON.stringify(W(parseInt(idx,10), key.replace(/\\(.)/g,"$1"))); }
  catch(e){ return m; }
});
fs.writeFileSync(path.join(__dirname,"body_cur.js"), body);
console.log("[written] body_cur.js", body.length);
