// ④ transform 插值正向验证 —— 纯 JS 复刻 W3C cubic-bezier easing + matrix 插值,
// 不依赖浏览器活体动画。用 golden_run1 (C=1) 闭合。
//
// z 的动画构造 (来自 body_cur.js 去混淆):
//   A(m[a]) = {
//     color:   ["#"+RGB(row[0..2]), "#"+RGB(row[3..5])],
//     transform:["rotate(0deg)", "rotate("+H(row[6],60,360,true)+"deg)"],
//     easing:  "cubic-bezier("+row.slice(7).map((v,i)=>H(v, i%2?-1:0, 1))+")"
//   }
//   H=(n,t,r,c)=> { u=(n*(r-t))/255+t; return c?floor(u):+u.toFixed(2) }
//   E: W=el.animate(A(row), dur=4096); W.pause(); W.currentTime = round(C/10)*10
//   然后读 getComputedStyle(el).color / .transform
//
// 关键: easing 的 cubic-bezier 把动画"时间进度" t∈[0,1] 映射到"值进度" p。
//   t = currentTime / duration = (round(C/10)*10) / 4096
//   p = cubicBezierEasing(t)  ← 注意 bezier 是 (x:时间, y:值进度) 的曲线
//   color_channel = round(start + (end-start)*p)
//   rotateDeg     = 0 + (rotateTo-0)*p
//   matrix        = [cos, sin, -sin, cos, 0, 0] (rotate 的 2D 矩阵)

// ---- H 插值映射 ----
function H(n, t, r, c) {
  const u = (n * (r - t)) / 255 + t;
  return c ? Math.floor(u) : +u.toFixed(2);
}

// ---- cubic-bezier easing 求值 (W3C / Chrome 实现) ----
// 给定控制点 (x1,y1,x2,y2), 端点固定 (0,0)(1,1)。
// 输入动画时间分数 x∈[0,1], 解出 t 使 bezierX(t)=x, 再返回 bezierY(t)。
function cubicBezier(x1, y1, x2, y2) {
  const NEWTON_ITER = 8, NEWTON_MIN = 1e-7, SUBDIV_ITER = 12, SUBDIV_EPS = 1e-7;
  const A = (a, b) => 1 - 3 * b + 3 * a;
  const B = (a, b) => 3 * b - 6 * a;
  const C = (a) => 3 * a;
  const calc = (t, a, b) => ((A(a, b) * t + B(a, b)) * t + C(a)) * t;
  const slope = (t, a, b) => 3 * A(a, b) * t * t + 2 * B(a, b) * t + C(a);

  function tForX(x) {
    let t = x;
    for (let i = 0; i < NEWTON_ITER; i++) {
      const s = slope(t, x1, x2);
      if (s === 0) break;
      const xv = calc(t, x1, x2) - x;
      t -= xv / s;
    }
    // bisection fallback
    let lo = 0, hi = 1, tt = x;
    if (t < lo) t = lo;
    if (t > hi) t = hi;
    for (let i = 0; i < SUBDIV_ITER; i++) {
      const xv = calc(tt, x1, x2);
      if (Math.abs(xv - x) < SUBDIV_EPS) return tt;
      if (xv < x) lo = tt; else hi = tt;
      tt = (lo + hi) / 2;
    }
    return t;
  }
  return (x) => {
    if (x1 === y1 && x2 === y2) return x; // linear
    return calc(tForX(x), y1, y2);
  };
}

// ---- 正向算 transform / color ----
function forward(row, C) {
  // easing 参数: row.slice(7) = [row7,row8,row9,row10], H(v, i%2?-1:0, 1)
  const e = row.slice(7).map((v, i) => H(v, i % 2 ? -1 : 0, 1));
  const [x1, y1, x2, y2] = e;
  const rotateTo = H(row[6], 60, 360, true); // 整数 deg
  const dur = 4096;
  const ct = Math.round(C / 10) * 10;        // ← 解出的公式
  const xFrac = ct / dur;
  const ease = cubicBezier(x1, y1, x2, y2);
  const p = ease(xFrac);                      // 值进度

  // color: start=row[0..2], end=row[3..5]
  const col = [0, 1, 2].map(i => Math.round(row[i] + (row[i + 3] - row[i]) * p));

  // transform: rotate(deg*p) -> 2D matrix
  const deg = rotateTo * p;
  const rad = deg * Math.PI / 180;
  const cos = Math.cos(rad), sin = Math.sin(rad);
  // CSS matrix(a,b,c,d,e,f) for rotate = [cos, sin, -sin, cos, 0, 0]
  const matrix = [cos, sin, -sin, cos, 0, 0];

  return { e, x1, y1, x2, y2, rotateTo, ct, xFrac, p, col, deg, matrix };
}

// ---- 拼装 (复刻 ⑤, 与 salt_assembly.py 等价) ----
function assembleToken(n) {
  const fixed = parseFloat(n.toFixed(2));
  return fixed.toString(16).replace(/[.-]/g, "");
}
function buildSuffix(col, matrix) {
  // computed color "rgb(r, g, b)" -> 数字 r,g,b ; transform "matrix(a,b,c,d,e,f)"
  // z: (""+cs.color+cs.transform).match(/([\d.-]+)/g)
  const nums = [...col, ...matrix];
  // color hex: 直接整数 RGB -> 但 z 走的是 toString(16) of toFixed(2)!
  //   整数 84 -> (84).toFixed(2)=84.00 -> parseFloat=84 -> (84).toString(16)="54"
  return nums.map(assembleToken).join("");
}

// ---- golden_run1: C=1, row=[221,181,84,119,84,7,89,182,73,226,187] ----
const run1 = {
  name: "run1 C=1",
  row: [221, 181, 84, 119, 84, 7, 89, 182, 73, 226, 187],
  C: 1,
  realSuffix: "ddb554100100",
};

for (const run of [run1]) {
  const f = forward(run.row, run.C);
  const suffix = buildSuffix(f.col, f.matrix);
  console.log(`\n=== ${run.name} ===`);
  console.log("easing cubic-bezier(" + f.e.join(",") + ")");
  console.log("rotateTo deg =", f.rotateTo, " ct =", f.ct, "ms  xFrac =", f.xFrac, " p =", f.p);
  console.log("color rgb =", f.col, " -> hex", f.col.map(v => v.toString(16).padStart(2, "0")).join(""));
  console.log("deg =", f.deg, " matrix =", f.matrix);
  console.log("suffix got  :", suffix);
  console.log("suffix want :", run.realSuffix);
  console.log(suffix === run.realSuffix ? "*** PASS ***" : "*** FAIL ***");
}
