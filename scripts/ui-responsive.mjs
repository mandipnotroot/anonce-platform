// SPDX-License-Identifier: AGPL-3.0-only
// Focused browser check for workspace navigation at responsive breakpoints.
import assert from "node:assert/strict";
import { mkdir, readFile } from "node:fs/promises";
import { chromium } from "playwright";

const webURL = new URL("../web/", import.meta.url);
const css = await readFile(new URL("styles.css", webURL), "utf8");
const font = await readFile(new URL("assets/geist-variable.woff2", webURL));
const icons = new Map(
  await Promise.all(
    ["house", "building-2", "user-round"].map(async (name) => [
      name,
      (await readFile(new URL(`assets/icons/${name}.svg`, webURL))).toString(
        "base64",
      ),
    ]),
  ),
);
const ui = await readFile(new URL("ui.js", webURL), "utf8");
const frameStart = ui.indexOf('function frame(body, title = "Workspace") {');
const assignmentStart = ui.indexOf("root.innerHTML = ", frameStart);
const assignmentEnd =
  ui.indexOf(";\n  renderButtonIcons();", assignmentStart) + 1;
assert.ok(
  frameStart >= 0 && assignmentStart >= 0 && assignmentEnd > assignmentStart,
  "frame markup found in ui.js",
);
const markupAssignment = ui.slice(assignmentStart, assignmentEnd);
const widths = [320, 375, 390, 640, 768, 1280, 1365];
const artifactDir = process.env.ANONCE_UI_ARTIFACT_DIR || "/tmp/anonce-ui";
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({ colorScheme: "light" });
  await page.setViewportSize({ width: 320, height: 900 });
  const icon = (name) =>
    `<img class="icon" src="data:image/svg+xml;base64,${icons.get(name)}" alt="" aria-hidden="true">`;
  const root = { innerHTML: "" };
  const renderFrame = new Function(
    "root",
    "active",
    "session",
    "sourceURL",
    "body",
    "title",
    "icon",
    "esc",
    "sourceLink",
    "workspaceLabel",
    markupAssignment,
  );
  const workspaceName =
    "Design workspace with a deliberately long organization name for responsive header checks";
  const workspaceLabel = `<div class="workspace-label" aria-label="Current workspace: ${workspaceName}"><span class="workspace-icon">${icon("building-2")}</span><strong>${workspaceName}</strong></div>`;
  renderFrame(
    root,
    "",
    { email: "member.with.a.long.address@example.organization.example" },
    "#",
    '<div style="height:1600px">Scrollable workspace content</div>',
    "Overview",
    icon,
    (value) => String(value),
    "<a></a>",
    workspaceLabel,
  );
  await page.setContent(
    `<meta name="viewport" content="width=device-width, initial-scale=1"><style>${css.replace("url('./assets/geist-variable.woff2')", `url('data:font/woff2;base64,${font.toString("base64")}')`)}</style>${root.innerHTML}`,
  );
  await page.evaluate(async () => {
    await document.fonts.ready;
    await Promise.all(
      [...document.querySelectorAll("img")].map((image) => image.decode()),
    );
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
          linkHeights: links.map((link) =>
            Math.round(link.getBoundingClientRect().height),
          ),
          linkSizes: links.map((link) => [link.scrollWidth, link.clientWidth]),
          labelFits: links.every(
            (link) => link.scrollWidth <= link.clientWidth + 1,
          ),
          activeCount: links.filter(
            (link) => link.getAttribute("aria-current") === "page",
          ).length,
          accountLabel: links[2].getAttribute("aria-label"),
          workspace: document.querySelector(".workspace-label strong")
            ?.textContent,
          workspaceLabel: document
            .querySelector(".workspace-label")
            ?.getAttribute("aria-label"),
          desktopSpacing: getComputedStyle(
            document.querySelector(".nav-label span + span"),
            "::before",
          ).content,
          geometry: links.map((link) => {
            const icon = link.querySelector(".icon").getBoundingClientRect();
            const label = link
              .querySelector(".nav-label, .nav-item > span:not(.nav-label)")
              .getBoundingClientRect();
            return {
              iconRight: icon.right,
              iconBottom: icon.bottom,
              iconCenter: icon.left + icon.width / 2,
              labelLeft: label.left,
              labelTop: label.top,
              labelCenter: label.left + label.width / 2,
            };
          }),
        };
      });
      console.log(JSON.stringify({ ...result, colorScheme }));
      assert.equal(
        result.documentWidth,
        width,
        `horizontal overflow at ${width}px (${colorScheme})`,
      );
      assert.equal(
        result.labelFits,
        true,
        `navigation label overflow at ${width}px (${colorScheme})`,
      );
      assert.equal(result.activeCount, 1);
      assert.equal(result.accountLabel, "Account and recovery");
      assert.equal(result.workspace, workspaceName);
      assert.equal(
        result.workspaceLabel,
        `Current workspace: ${workspaceName}`,
      );
      assert.equal(result.desktopSpacing, '" "');
      if (width <= 640) {
        assert.equal(
          await page
            .locator(".nav")
            .evaluate((nav) => getComputedStyle(nav).position),
          "fixed",
        );
        assert.equal(
          await page
            .locator(".nav")
            .evaluate(
              (nav) =>
                Math.abs(nav.getBoundingClientRect().bottom - innerHeight) <= 1,
            ),
          true,
          `bottom navigation geometry mismatch: ${await page
            .locator(".nav")
            .evaluate((nav) =>
              JSON.stringify({
                bottom: nav.getBoundingClientRect().bottom,
                height: innerHeight,
                clientHeight: document.documentElement.clientHeight,
                ancestors: [
                  ...(function* () {
                    for (
                      let node = nav.parentElement;
                      node;
                      node = node.parentElement
                    )
                      yield node;
                  })(),
                ].map((node) => ({
                  tag: node.tagName,
                  className: node.className,
                  position: getComputedStyle(node).position,
                  transform: getComputedStyle(node).transform,
                  filter: getComputedStyle(node).filter,
                  backdropFilter: getComputedStyle(node).backdropFilter,
                  contain: getComputedStyle(node).contain,
                  willChange: getComputedStyle(node).willChange,
                })),
              }),
            )}`,
        );
        assert.equal(
          new Set(result.linkHeights).size,
          1,
          `uneven tile heights at ${width}px`,
        );
        for (const {
          iconCenter,
          labelCenter,
          iconBottom,
          labelTop,
        } of result.geometry) {
          assert.ok(
            Math.abs(iconCenter - labelCenter) <= 1,
            `icon and label not centered at ${width}px`,
          );
          assert.ok(
            labelTop > iconBottom,
            `mobile label does not follow icon at ${width}px`,
          );
        }
      } else {
        assert.equal(
          await page
            .locator(".site-header")
            .evaluate((header) => getComputedStyle(header).position),
          "sticky",
        );
        for (const { iconRight, labelLeft } of result.geometry)
          assert.ok(
            labelLeft - iconRight >= 10,
            `desktop icon/text gap below 11px at ${width}px`,
          );
      }
      await page.evaluate(() => scrollTo(0, 300));
      assert.ok(
        await page.evaluate(() => scrollY >= 299),
        `page did not scroll at ${width}px`,
      );
      if (width <= 640) {
        assert.equal(
          await page
            .locator(".nav")
            .evaluate(
              (nav) =>
                Math.abs(nav.getBoundingClientRect().bottom - innerHeight) <= 1,
            ),
          true,
          `bottom navigation lost after scroll at ${width}px`,
        );
        assert.equal(
          await page.evaluate(
            () =>
              document.documentElement.scrollHeight >=
              document.querySelector(".nav").offsetHeight +
                document.querySelector("main").scrollHeight,
          ),
          true,
          `content clearance missing at ${width}px`,
        );
        await page.evaluate(() =>
          scrollTo(0, document.documentElement.scrollHeight),
        );
        assert.ok(
          await page.evaluate(
            () =>
              document.querySelector(".site-footer").getBoundingClientRect()
                .bottom <=
              document.querySelector(".nav").getBoundingClientRect().top,
          ),
          `footer hidden behind bottom navigation at ${width}px`,
        );
      } else
        assert.equal(
          await page
            .locator(".site-header")
            .evaluate((header) => header.getBoundingClientRect().top >= -1),
          true,
          `sticky header lost after scroll at ${width}px`,
        );
      assert.equal(
        await page
          .locator(".site-header")
          .evaluate((header) => header.scrollWidth <= header.clientWidth),
        true,
        `header content overflow at ${width}px`,
      );
      await page.evaluate(() => scrollTo(0, 0));
      if (width === 320 || width === 1280)
        await page.screenshot({
          path: `${artifactDir}/navigation-${width}-${colorScheme}.png`,
          fullPage: true,
        });
    }
  }
} finally {
  await browser.close();
}
