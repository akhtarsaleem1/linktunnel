/**
 * Zero-dependency ISO/IEC 18004 QR Code Generator (Byte Mode, Versions 1..16, ECC L & M).
 */

const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) {
    GF_EXP[i] = GF_EXP[i - 255];
  }
})();

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function rsGeneratorPoly(degree) {
  let poly = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array(poly.length + 1).fill(0);
    const root = GF_EXP[i];
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], root);
    }
    poly = next;
  }
  return poly;
}

function rsComputeEcc(data, eccLen) {
  const gen = rsGeneratorPoly(eccLen);
  const res = new Uint8Array(eccLen);
  for (let i = 0; i < data.length; i++) {
    const factor = data[i] ^ res[0];
    res.copyWithin(0, 1);
    res[eccLen - 1] = 0;
    if (factor !== 0) {
      for (let j = 0; j < eccLen; j++) {
        res[j] ^= gfMul(gen[j + 1], factor);
      }
    }
  }
  return res;
}

// [g1Blocks, g1Data, g2Blocks, g2Data, eccPerBlock] for Versions 1..16
const ECC_TABLE = {
  L: [
    null,
    [1, 19, 0, 0, 7],
    [1, 34, 0, 0, 10],
    [1, 55, 0, 0, 15],
    [1, 80, 0, 0, 20],
    [1, 108, 0, 0, 26],
    [2, 68, 0, 0, 18],
    [2, 78, 0, 0, 20],
    [2, 97, 0, 0, 24],
    [2, 116, 0, 0, 30],
    [2, 68, 2, 69, 18],
    [4, 81, 0, 0, 20],
    [2, 92, 2, 93, 24],
    [4, 107, 0, 0, 26],
    [3, 115, 1, 116, 30],
    [5, 87, 1, 88, 22],
    [5, 98, 1, 99, 24],
  ],
  M: [
    null,
    [1, 16, 0, 0, 10],
    [1, 28, 0, 0, 16],
    [1, 44, 0, 0, 26],
    [2, 32, 0, 0, 18],
    [2, 43, 0, 0, 24],
    [4, 27, 0, 0, 16],
    [4, 31, 0, 0, 18],
    [2, 38, 2, 39, 22],
    [3, 36, 2, 37, 22],
    [4, 43, 1, 44, 26],
    [1, 50, 4, 51, 30],
    [6, 36, 2, 37, 22],
    [8, 37, 1, 38, 22],
    [4, 40, 5, 41, 24],
    [5, 41, 5, 42, 24],
    [7, 45, 3, 46, 28],
  ],
};

const ALIGNMENT_CENTERS = [
  null,
  [],
  [6, 18],
  [6, 22],
  [6, 26],
  [6, 30],
  [6, 34],
  [6, 22, 38],
  [6, 24, 42],
  [6, 26, 46],
  [6, 28, 50],
  [6, 30, 54],
  [6, 32, 58],
  [6, 34, 62],
  [6, 26, 46, 66],
  [6, 26, 48, 70],
  [6, 26, 50, 74],
];

const REMAINDER_BITS = [0, 0, 7, 7, 7, 7, 7, 0, 0, 0, 0, 0, 0, 0, 3, 3, 3];

function computeBchFormatInfo(eccLevel, maskPattern) {
  const eccBits = eccLevel === 'L' ? 0b01 : 0b00; // M = 00, L = 01
  const data = (eccBits << 3) | (maskPattern & 7);
  let rem = data << 10;
  const gen = 0x537;
  for (let i = 14; i >= 10; i--) {
    if ((rem >> i) & 1) rem ^= gen << (i - 10);
  }
  return ((data << 10) | rem) ^ 0x5412;
}

function computeBchVersionInfo(version) {
  let rem = version << 12;
  const gen = 0x1f25;
  for (let i = 17; i >= 12; i--) {
    if ((rem >> i) & 1) rem ^= gen << (i - 12);
  }
  return (version << 12) | rem;
}

function selectVersion(byteLength, eccLevel) {
  const table = ECC_TABLE[eccLevel] || ECC_TABLE.M;
  for (let ver = 1; ver < table.length; ver++) {
    const [g1B, g1D, g2B, g2D] = table[ver];
    const totalDataCodewords = g1B * g1D + g2B * g2D;
    const headerBits = 4 + (ver <= 9 ? 8 : 16);
    const availableBytes = Math.floor((totalDataCodewords * 8 - headerBits) / 8);
    if (byteLength <= availableBytes) return ver;
  }
  return null;
}

function buildCodewords(bytes, version, eccLevel) {
  const [g1B, g1D, g2B, g2D, eccLen] = ECC_TABLE[eccLevel][version];
  const totalData = g1B * g1D + g2B * g2D;
  const bits = [];

  const pushBits = (val, len) => {
    for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1);
  };

  // Mode indicator: Byte = 0100
  pushBits(0b0100, 4);
  pushBits(bytes.length, version <= 9 ? 8 : 16);
  for (const b of bytes) pushBits(b, 8);

  const maxDataBits = totalData * 8;
  const terminatorLen = Math.min(4, maxDataBits - bits.length);
  pushBits(0, terminatorLen);
  while (bits.length % 8 !== 0) bits.push(0);

  const dataCodewords = new Uint8Array(totalData);
  for (let i = 0; i < bits.length / 8; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) byte = (byte << 1) | bits[i * 8 + b];
    dataCodewords[i] = byte;
  }
  let padToggle = 0;
  for (let i = bits.length / 8; i < totalData; i++) {
    dataCodewords[i] = padToggle === 0 ? 0xec : 0x11;
    padToggle ^= 1;
  }

  // Split into blocks and compute RS ECC
  const dataBlocks = [];
  const eccBlocks = [];
  let offset = 0;
  for (let b = 0; b < g1B; b++) {
    const blk = dataCodewords.subarray(offset, offset + g1D);
    dataBlocks.push(blk);
    eccBlocks.push(rsComputeEcc(blk, eccLen));
    offset += g1D;
  }
  for (let b = 0; b < g2B; b++) {
    const blk = dataCodewords.subarray(offset, offset + g2D);
    dataBlocks.push(blk);
    eccBlocks.push(rsComputeEcc(blk, eccLen));
    offset += g2D;
  }

  const out = [];
  const maxD = Math.max(g1D, g2D);
  for (let i = 0; i < maxD; i++) {
    for (const blk of dataBlocks) {
      if (i < blk.length) out.push(blk[i]);
    }
  }
  for (let i = 0; i < eccLen; i++) {
    for (const blk of eccBlocks) {
      out.push(blk[i]);
    }
  }
  return new Uint8Array(out);
}

function buildMatrixTemplate(version) {
  const size = version * 4 + 17;
  const modules = Array.from({ length: size }, () => new Uint8Array(size));
  const isFunc = Array.from({ length: size }, () => new Uint8Array(size));

  const setFunc = (r, c, dark) => {
    if (r < 0 || r >= size || c < 0 || c >= size) return;
    modules[r][c] = dark ? 1 : 0;
    isFunc[r][c] = 1;
  };

  const drawFinder = (r0, c0) => {
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) {
        const r = r0 + dr;
        const c = c0 + dc;
        if (r < 0 || r >= size || c < 0 || c >= size) continue;
        const inBorder = dr === -1 || dr === 7 || dc === -1 || dc === 7;
        const dark =
          !inBorder &&
          (dr === 0 ||
            dr === 6 ||
            dc === 0 ||
            dc === 6 ||
            (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4));
        setFunc(r, c, dark);
      }
    }
  };

  drawFinder(0, 0);
  drawFinder(0, size - 7);
  drawFinder(size - 7, 0);

  // Timing patterns
  for (let i = 8; i < size - 8; i++) {
    setFunc(6, i, i % 2 === 0);
    setFunc(i, 6, i % 2 === 0);
  }

  // Alignment patterns
  const centers = ALIGNMENT_CENTERS[version];
  for (const cr of centers) {
    for (const cc of centers) {
      if (isFunc[cr][cc]) continue;
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          const dark = Math.max(Math.abs(dr), Math.abs(dc)) !== 1;
          setFunc(cr + dr, cc + dc, dark);
        }
      }
    }
  }

  // Reserve format info modules + dark module
  for (let i = 0; i <= 8; i++) {
    if (i !== 6) {
      setFunc(8, i, false);
      setFunc(i, 8, false);
    }
  }
  for (let i = size - 8; i < size; i++) {
    setFunc(8, i, false);
  }
  for (let i = size - 7; i < size; i++) {
    setFunc(i, 8, false);
  }
  setFunc(size - 8, 8, true); // Dark module

  // Reserve and place version info for version >= 7
  if (version >= 7) {
    const vBits = computeBchVersionInfo(version);
    for (let i = 0; i < 18; i++) {
      const bit = ((vBits >> i) & 1) === 1;
      const a = Math.floor(i / 3);
      const b = size - 11 + (i % 3);
      setFunc(a, b, bit);
      setFunc(b, a, bit);
    }
  }

  return { size, modules, isFunc };
}

function placeDataBits(template, codewords, remainderBits) {
  const { size, modules, isFunc } = template;
  const totalBits = codewords.length * 8 + remainderBits;
  let bitIdx = 0;

  const nextBit = () => {
    if (bitIdx >= codewords.length * 8) {
      bitIdx++;
      return 0;
    }
    const byte = codewords[bitIdx >> 3];
    const bit = (byte >> (7 - (bitIdx & 7))) & 1;
    bitIdx++;
    return bit;
  };

  let upward = true;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let step = 0; step < size; step++) {
      const r = upward ? size - 1 - step : step;
      for (let dx = 0; dx < 2; dx++) {
        const c = right - dx;
        if (!isFunc[r][c] && bitIdx < totalBits) {
          modules[r][c] = nextBit();
        }
      }
    }
    upward = !upward;
  }
}

function applyMaskAndFormat(template, eccLevel, maskPattern) {
  const { size, modules, isFunc } = template;
  const out = modules.map((row) => new Uint8Array(row));

  const maskFn = (r, c) => {
    switch (maskPattern) {
      case 0: return (r + c) % 2 === 0;
      case 1: return r % 2 === 0;
      case 2: return c % 3 === 0;
      case 3: return (r + c) % 3 === 0;
      case 4: return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
      case 5: return ((r * c) % 2) + ((r * c) % 3) === 0;
      case 6: return (((r * c) % 2) + ((r * c) % 3)) % 2 === 0;
      case 7: return (((r + c) % 2) + ((r * c) % 3)) % 2 === 0;
      default: return false;
    }
  };

  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (!isFunc[r][c] && maskFn(r, c)) {
        out[r][c] ^= 1;
      }
    }
  }

  // Write 15-bit format information
  const fmt = computeBchFormatInfo(eccLevel, maskPattern);
  for (let i = 0; i < 6; i++) out[8][i] = (fmt >> (14 - i)) & 1;
  out[8][7] = (fmt >> 8) & 1;
  out[8][8] = (fmt >> 7) & 1;
  out[7][8] = (fmt >> 6) & 1;
  for (let i = 9; i < 15; i++) out[14 - i][8] = (fmt >> (14 - i)) & 1;

  for (let i = 0; i < 7; i++) out[size - 1 - i][8] = (fmt >> (14 - i)) & 1;
  for (let i = 7; i < 15; i++) out[8][size - 15 + i] = (fmt >> (14 - i)) & 1;

  return out;
}

function penaltyScore(grid) {
  const size = grid.length;
  let score = 0;

  // Rule 1: 5+ consecutive same-color modules in row/col
  for (let r = 0; r < size; r++) {
    let runColor = grid[r][0];
    let runLen = 1;
    let colColor = grid[0][r];
    let colLen = 1;
    for (let c = 1; c < size; c++) {
      if (grid[r][c] === runColor) {
        runLen++;
      } else {
        if (runLen >= 5) score += 3 + (runLen - 5);
        runColor = grid[r][c];
        runLen = 1;
      }
      if (grid[c][r] === colColor) {
        colLen++;
      } else {
        if (colLen >= 5) score += 3 + (colLen - 5);
        colColor = grid[c][r];
        colLen = 1;
      }
    }
    if (runLen >= 5) score += 3 + (runLen - 5);
    if (colLen >= 5) score += 3 + (colLen - 5);
  }

  // Rule 2: 2x2 blocks
  for (let r = 0; r < size - 1; r++) {
    for (let c = 0; c < size - 1; c++) {
      const v = grid[r][c];
      if (grid[r][c + 1] === v && grid[r + 1][c] === v && grid[r + 1][c + 1] === v) {
        score += 3;
      }
    }
  }

  // Rule 3: 1:1:3:1:1 pattern with 4 light modules on either side
  const matchPattern = (arr, idx) => {
    const p1 = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
    const p2 = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1];
    if (idx + 11 > arr.length) return false;
    let m1 = true;
    let m2 = true;
    for (let k = 0; k < 11; k++) {
      if (arr[idx + k] !== p1[k]) m1 = false;
      if (arr[idx + k] !== p2[k]) m2 = false;
    }
    return m1 || m2;
  };
  for (let r = 0; r < size; r++) {
    const colArr = new Uint8Array(size);
    for (let i = 0; i < size; i++) colArr[i] = grid[i][r];
    for (let c = 0; c <= size - 11; c++) {
      if (matchPattern(grid[r], c)) score += 40;
      if (matchPattern(colArr, c)) score += 40;
    }
  }

  // Rule 4: dark proportion
  let dark = 0;
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (grid[r][c]) dark++;
    }
  }
  const percent = (dark * 100) / (size * size);
  const k = Math.floor(Math.abs(percent - 50) / 5);
  score += k * 10;
  return score;
}

/**
 * Generates a QR Code matrix (`Uint8Array[]`) for arbitrary UTF-8 text.
 */
export function generateQrMatrix(text, preferredEcc = 'M') {
  const bytes = Buffer.from(String(text), 'utf8');
  let ecc = preferredEcc;
  let version = selectVersion(bytes.length, ecc);
  if (!version && ecc === 'M') {
    ecc = 'L';
    version = selectVersion(bytes.length, ecc);
  }
  if (!version) {
    throw new Error(`QR payload too long (${bytes.length} bytes, max ~520 bytes)`);
  }

  const codewords = buildCodewords(bytes, version, ecc);
  const template = buildMatrixTemplate(version);
  placeDataBits(template, codewords, REMAINDER_BITS[version]);

  let bestGrid = null;
  let bestScore = Infinity;
  let bestMask = 0;
  for (let mask = 0; mask < 8; mask++) {
    const grid = applyMaskAndFormat(template, ecc, mask);
    const sc = penaltyScore(grid);
    if (sc < bestScore) {
      bestScore = sc;
      bestGrid = grid;
      bestMask = mask;
    }
  }

  return { version, ecc, mask: bestMask, size: template.size, matrix: bestGrid };
}

/**
 * Renders a crisp SVG QR code with quiet zone.
 */
export function generateQrSvg(text, { ecc = 'M', margin = 4, darkColor = '#0f172a', lightColor = '#ffffff' } = {}) {
  const { size, matrix, version } = generateQrMatrix(text, ecc);
  const total = size + margin * 2;
  let path = '';
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (matrix[r][c]) {
        path += `M${c + margin},${r + margin}h1v1h-1z`;
      }
    }
  }
  return {
    version,
    size,
    svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${total}" shape-rendering="crispEdges"><rect width="${total}" height="${total}" fill="${lightColor}"/><path d="${path}" fill="${darkColor}"/></svg>`,
  };
}
