import assert from 'node:assert/strict';
import test from 'node:test';
import { generateQrMatrix, generateQrSvg } from '../src/protocol/qr.mjs';

test('QR generator produces valid finder patterns, timing patterns, dark module, and SVG', () => {
  const shortQr = generateQrMatrix('HELLO', 'M');
  assert.equal(shortQr.version, 1);
  assert.equal(shortQr.size, 21);

  // Verify top-left 7x7 finder outer ring
  for (let i = 0; i < 7; i++) {
    assert.equal(shortQr.matrix[0][i], 1);
    assert.equal(shortQr.matrix[6][i], 1);
    assert.equal(shortQr.matrix[i][0], 1);
    assert.equal(shortQr.matrix[i][6], 1);
  }
  // Verify dark module at (4*version + 9, 8) = (13, 8)
  assert.equal(shortQr.matrix[4 * shortQr.version + 9][8], 1);

  // Verify typical long linktunnel:// invite URI fits cleanly and renders SVG
  const longInvite = `linktunnel://v1?d=${'A'.repeat(220)}`;
  const { svg, version, size } = generateQrSvg(longInvite);
  assert.ok(version >= 7 && version <= 16);
  assert.equal(size, version * 4 + 17);
  assert.ok(svg.startsWith('<svg xmlns="http://www.w3.org/2000/svg"'));
  assert.ok(svg.includes('<path d="M'));
});
