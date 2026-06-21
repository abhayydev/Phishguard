/**
 * generate-icons.js
 * Generates PhishGuard extension icons programmatically using the Canvas API.
 * Run in a browser console or with a headless browser to produce PNG files.
 *
 * In a Node.js environment, use the `canvas` npm package:
 *   npm install canvas
 *   node generate-icons.js
 *
 * Or simply use any image editor to create icons from the specification below.
 */

// Icon specification:
// - Background: #6366f1 (indigo) to #4f46e5 gradient
// - Symbol: ⚡ lightning bolt in white (Unicode U+26A1)
// - Sizes: 16×16, 32×32, 48×48, 128×128

// For manual creation, use these colors:
// Primary: #6366f1 (indigo-500)
// Secondary: #4f46e5 (indigo-600)
// Symbol color: #ffffff
// Shape: circle with slight corner rounding

// SVG source for generating PNG icons:
const svgTemplate = (size) => `<?xml version="1.0" encoding="UTF-8"?>
<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}"
     xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#6366f1"/>
      <stop offset="100%" style="stop-color:#4f46e5"/>
    </linearGradient>
  </defs>
  <rect width="${size}" height="${size}" rx="${size * 0.22}" fill="url(#bg)"/>
  <text
    x="${size / 2}" y="${size * 0.72}"
    text-anchor="middle"
    font-size="${size * 0.6}"
    font-family="Segoe UI Emoji, Apple Color Emoji, sans-serif"
    fill="white"
  >⚡</text>
</svg>`;

const sizes = [16, 32, 48, 128];

if (typeof module !== 'undefined') {
  // Node.js environment
  const fs = require('fs');
  const path = require('path');

  try {
    const { createCanvas } = require('canvas');

    sizes.forEach(size => {
      const canvas = createCanvas(size, size);
      const ctx = canvas.getContext('2d');

      // Background gradient
      const grad = ctx.createLinearGradient(0, 0, size, size);
      grad.addColorStop(0, '#6366f1');
      grad.addColorStop(1, '#4f46e5');

      // Rounded rectangle
      const r = size * 0.22;
      ctx.beginPath();
      ctx.moveTo(r, 0);
      ctx.lineTo(size - r, 0);
      ctx.quadraticCurveTo(size, 0, size, r);
      ctx.lineTo(size, size - r);
      ctx.quadraticCurveTo(size, size, size - r, size);
      ctx.lineTo(r, size);
      ctx.quadraticCurveTo(0, size, 0, size - r);
      ctx.lineTo(0, r);
      ctx.quadraticCurveTo(0, 0, r, 0);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();

      // Lightning bolt ⚡
      ctx.font = `${size * 0.58}px "Segoe UI Emoji", "Apple Color Emoji", sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = 'white';
      ctx.fillText('⚡', size / 2, size / 2 + size * 0.05);

      const buffer = canvas.toBuffer('image/png');
      fs.writeFileSync(path.join(__dirname, `icon${size}.png`), buffer);
      console.log(`✓ Generated icon${size}.png`);
    });
  } catch (e) {
    // Fallback: write SVG files instead
    console.log('canvas package not found — generating SVG files instead');
    sizes.forEach(size => {
      const svgPath = path.join(__dirname, `icon${size}.svg`);
      fs.writeFileSync(svgPath, svgTemplate(size));
      console.log(`✓ Generated icon${size}.svg (rename to .png after converting)`);
    });
  }
}

// Export SVG templates for use in other tools
if (typeof module !== 'undefined') module.exports = { svgTemplate, sizes };
console.log('Icon generation complete. Place icon*.png files in assets/icons/');
