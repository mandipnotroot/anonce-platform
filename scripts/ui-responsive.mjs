// SPDX-License-Identifier: AGPL-3.0-only
// Focused browser check for workspace navigation at responsive breakpoints.
import assert from "node:assert/strict";
import { mkdir, readFile } from "node:fs/promises";
import { chromium } from "playwright";

const webURL = new URL("../web/", import.meta.url);
const css = await readFile(new URL("styles.css", webURL), "utf8");
const font = await readFile(new URL("assets/geist-variable.woff2", webURL));
const icons = new Map(await Promise.all(["house", "building-2", "user-round"].map(async (name) => [name, (await readFile(new URL(`assets/icons/${name}.svg`, webURL))).toString("base64")])));
const ui = await readFile(new URL("ui.js", webURL), "utf8");
const frameStart = ui.indexOf("function frame(body, title = \"Workspace\") {");
const assignmentStart = ui.indexOf("root.innerHTML = ", frameStart);
const assignmentEnd = ui.indexOf(";\n  renderButtonIcons();", assignmentStart) + 1;
assert.ok(frameStart >= 0 && assignmentStart >= 0 && assignmentEnd > assignmentStart, "frame markup found in ui.js");
const markupAssignment = ui.slice(assignmentStart, assignmentEnd);
const widths = [320, 375, 390, 640, 768, 1280];
const artifactDir = process.env.ANONCE_UI_ARTIFACT_DIR || "/tmp/opencode/anonce-ui-responsive";
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({ colorScheme: "light" });
  const icon = (name) => `<img class="icon" src="data:image/svg+xml;base64,${icons.get(name)}" alt="" aria-hidden="true">`;
  const root = { innerHTML: "" };
  const renderFrame = new Function("root", "active", "session", "sourceURL", "body", "title", "icon", "esc", "sourceLink", "workspaceLabel", markupAssignment);
  const workspaceLabel = `<div class="workspace-label"><span class="workspace-icon">${icon("building-2")}</span><span><small>WORKSPACE</small><strong>Design workspace</strong></span></div>`;
  renderFrame(root, "", { email: "member@example.net" }, "#", "<div></div>", "Overview", icon, (value) => String(value), "<a></a>", workspaceLabel);
  await page.setContent(`<style>${css.replace("url('./assets/geist-variable.woff2')", `url('data:font/woff2;base64,${font.toString("base64")}')`)}</style>${root.innerHTML}`);
  await page.evaluate(async () => {
    await document.fonts.ready;
    await Promise.all([...document.querySelectorAll("img")].map((image) => image.decode()));
  });
  await mkdir(artifactDir, { recursive: true });
  for (const width of widths) {
    await page.setViewportSize({ width, height: 900 });
    for (const colorScheme of ["light", "dark"]) {
      await page.emulateMedia({ colorScheme });
      const result = await page.evaluate(() => {
        const nav = document.querySelector(".nav");
        const links = [...nav.querySelectorAll("a")];
        return {
          viewport: innerWidth,
          documentWidth: document.documentElement.scrollWidth,
          linkHeights: links.map((link) => Math.round(link.getBoundingClientRect().height)),
          linkSizes: links.map((link) => [link.scrollWidth, link.clientWidth]),
          labelFits: links.every((link) => link.scrollWidth <= link.clientWidth + 1),
          activeCount: links.filter((link) => link.getAttribute("aria-current") === "page").length,
          accountLabel: links[2].getAttribute("aria-label"),
          workspace: document.querySelector(".workspace-label strong")?.textContent,
          desktopSpacing: getComputedStyle(document.querySelector(".nav-label span + span"), "::before").content,
          geometry: links.map((link) => {
            const icon = link.querySelector(".icon").getBoundingClientRect();
            const label = link.querySelector(".nav-label, .nav-item > span:not(.nav-label)").getBoundingClientRect();
            return { iconRight: icon.right, iconBottom: icon.bottom, iconCenter: icon.left + icon.width / 2, labelLeft: label.left, labelTop: label.top, labelCenter: label.left + label.width / 2 };
          }),
        };
      });
      console.log(JSON.stringify({ ...result, colorScheme }));
      assert.equal(result.documentWidth, width, `horizontal overflow at ${width}px (${colorScheme})`);
      assert.equal(result.labelFits, true, `navigation label overflow at ${width}px (${colorScheme})`);
      assert.equal(result.activeCount, 1);
      assert.equal(result.accountLabel, "Account and recovery");
      assert.equal(result.workspace, "Design workspace");
      assert.equal(result.desktopSpacing, '" "');
      if (width <= 640) {
        assert.equal(new Set(result.linkHeights).size, 1, `uneven tile heights at ${width}px`);
        for (const { iconCenter, labelCenter, iconBottom, labelTop } of result.geometry) {
          assert.ok(Math.abs(iconCenter - labelCenter) <= 1, `icon and label not centered at ${width}px`);
          assert.ok(labelTop > iconBottom, `mobile label does not follow icon at ${width}px`);
        }
      } else {
        for (const { iconRight, labelLeft } of result.geometry) assert.ok(labelLeft - iconRight >= 10, `desktop icon/text gap below 11px at ${width}px`);
      }
      if (width === 320 || width === 1280) await page.screenshot({ path: `${artifactDir}/navigation-${width}-${colorScheme}.png`, fullPage: true });
    }
  }
} finally {
  await browser.close();
}
