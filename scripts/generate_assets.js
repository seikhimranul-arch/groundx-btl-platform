const fs = require('fs');
const path = require('path');

const CORAL = '#D85A30';
const INK = '#1F1D1B';
const G = {
  U: ["#...#","#...#","#...#","#...#","#...#","#...#",".###."],
  T: ["#####","..#..","..#..","..#..","..#..","..#..","..#.."],
  K: ["#...#","#..#.","#.#..","##...","#.#..","#..#.","#...#"],
  A: [".###.","#...#","#...#","#####","#...#","#...#","#...#"],
  L: ["#....","#....","#....","#....","#....","#....","#####"],
  V: ["#...#","#...#","#...#","#...#","#...#",".#.#.","..#.."],
  N: ["#...#","##..#","#.#.#","#..##","#...#","#...#","#...#"],
  G: [".###.","#...#","#....","#.###","#...#","#...#",".####"],
  E: ["#####","#....","#....","####.","#....","#....","#####"]
};

function generateSunSvg(cell = 12, options = {}) {
  const w = 260, h = 112;
  const cx = 130, cy = 84;
  let circles = [];
  
  for (let gx = -6; gx <= 6; gx++) {
    for (let gy = -6; gy <= 0; gy++) {
      const d = Math.hypot(gx, gy);
      if (d <= 6.5) {
        const r = d <= 3 ? cell * 0.32 : (d <= 5 ? cell * 0.27 : cell * 0.21);
        const fill = (options.core && d <= 3) ? CORAL : (options.sunFill || CORAL);
        circles.push(`<circle cx="${(cx + gx * cell).toFixed(1)}" cy="${(cy + gy * cell).toFixed(1)}" r="${r.toFixed(2)}" fill="${fill}"/>`);
      }
    }
  }
  
  for (let gx = -10; gx <= 10; gx++) {
    circles.push(`<circle cx="${(cx + gx * cell).toFixed(1)}" cy="${(cy + cell).toFixed(1)}" r="${(cell * 0.15).toFixed(2)}" fill="${options.ink || INK}" opacity="0.5"/>`);
  }
  
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" role="img">\n  ${circles.join('\n  ')}\n</svg>`;
}

function generateWordmarkSvg(options = {}) {
  const wc = 6;
  const fill = options.wordFill || INK;
  let circles = [];
  
  function addWord(str, x0, y0) {
    const w = str.length * 6 - 1;
    let x = x0 - (w * wc) / 2;
    for (const ch of str) {
      const glyph = G[ch];
      for (let r = 0; r < 7; r++) {
        for (let c = 0; c < 5; c++) {
          if (glyph[r][c] === '#') {
            circles.push(`<circle cx="${(x + c * wc + wc / 2).toFixed(1)}" cy="${(y0 + r * wc + wc / 2).toFixed(1)}" r="${(wc * 0.4).toFixed(2)}" fill="${fill}"/>`);
          }
        }
      }
      x += 6 * wc;
    }
  }
  
  addWord("UTKAL", 150, 4);
  addWord("VANTAGE", 150, 60);
  
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 300 120" role="img">\n  ${circles.join('\n  ')}\n</svg>`;
}

const assetsDir = path.join(__dirname, '..', 'assets');
if (!fs.existsSync(assetsDir)) fs.mkdirSync(assetsDir, { recursive: true });

fs.writeFileSync(path.join(assetsDir, 'mark.svg'), generateSunSvg(12, { sunFill: CORAL, ink: INK }));
fs.writeFileSync(path.join(assetsDir, 'mark-white.svg'), generateSunSvg(12, { sunFill: '#FFF6F0', ink: '#FFF6F0' }));
fs.writeFileSync(path.join(assetsDir, 'wordmark.svg'), generateWordmarkSvg({ wordFill: INK }));
fs.writeFileSync(path.join(assetsDir, 'wordmark-white.svg'), generateWordmarkSvg({ wordFill: '#FFF6F0' }));

console.log('Generated brand assets in assets/ directory.');
