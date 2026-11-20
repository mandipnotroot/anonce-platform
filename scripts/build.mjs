// SPDX-License-Identifier: AGPL-3.0-only
import { build } from "esbuild";

// Bundle dependency-bearing modules locally; application/UI modules stay vanilla.
for (const module of ["crypto", "storage"])
  await build({
    entryPoints: [`web/${module}.js`],
    outfile: `web/${module}.bundle.js`,
    bundle: true,
    format: "esm",
    platform: "browser",
    target: ["es2022"],
    legalComments: "linked",
    sourcemap: false,
    minify: true,
  });
