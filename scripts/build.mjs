// SPDX-License-Identifier: AGPL-3.0-only
import { build } from 'esbuild';

// Only cryptographic modules are bundled. Application/UI modules remain vanilla
// JavaScript; all cryptographic dependencies are served from this local artifact.
await build({
  entryPoints: ['web/crypto.js'],
  outfile: 'web/crypto.bundle.js',
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: ['es2022'],
  legalComments: 'linked',
  sourcemap: false,
  minify: true,
});
