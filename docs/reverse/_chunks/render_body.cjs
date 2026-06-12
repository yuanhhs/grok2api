// 把签名函数体里的 W(idx,"key") 全部替换成解码后的明文字符串，渲染成可读源码。
const fs = require("fs");
const { W } = require("./decoder.cjs");

const L1 = fs.readFileSync("sig_L1.txt", "utf8");
const anchor = 'n.s(["default",0,';
const start = L1.indexOf(anchor);
// 取到该模块结尾（TURBOPACK push 的闭合）；够长即可
let body = L1.slice(start, start + 14000);

// 替换 W(idx,"key")  和  W(expr,"key")（含算术混淆，如 (r=-362,W(r- -751,"#x")))
// 先处理简单形式 W(\d+,"...")
body = body.replace(/W\((\d+),"((?:[^"\\]|\\.)*)"\)/g, (m, idx, key) => {
  try {
    const s = W(parseInt(idx, 10), key);
    return JSON.stringify(s);
  } catch (e) {
    return m;
  }
});

fs.writeFileSync("body_rendered.js", body);
console.log("[written] body_rendered.js len", body.length);
// 打印含 Q 索引访问的片段：找形如 [数字] 的下标，以及变量赋值
const idxHits = [...body.matchAll(/\[\s*(\d{1,2})\s*\]/g)].map(m => m[1]);
console.log("[numeric-index hits]", idxHits.join(","));
