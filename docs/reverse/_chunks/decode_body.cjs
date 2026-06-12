// 解码签名函数体内所有 W(idx,"key") 调用 -> 明文
const fs = require("fs");
const { W } = require("./decoder.cjs");

const L1 = fs.readFileSync(__dirname + "/sig.js", "utf8").split("\n")[1];
const start = L1.indexOf('n.s(["default"');
const body = L1.slice(start);
console.log("[body] len", body.length);

const re = /W\((\d+),"((?:[^"\\]|\\.)*)"\)/g;
let m, seen = new Set(), rows = [];
while ((m = re.exec(body))) {
  const idx = +m[1];
  const key = m[2].replace(/\\(.)/g, "$1");
  const sig = idx + "|" + key;
  if (seen.has(sig)) continue;
  seen.add(sig);
  let val;
  try { val = W(idx, key); } catch (e) { val = "ERR:" + e.message; }
  rows.push([idx, key, val]);
}
console.log("[calls]", rows.length, "unique\n");
for (const [i, k, v] of rows) console.log(i, JSON.stringify(v));
