// SPDX-License-Identifier: AGPL-3.0-only
// Focused browser check for workspace navigation at responsive breakpoints.
import assert from "node:assert/strict";
import { mkdir, readFile } from "node:fs/promises";
import { chromium } from "playwright";

const webURL = new URL("../web/", import.meta.url);
const css = await readFile(new URL("styles.css", webURL), "utf8");
const font = await readFile(new URL("assets/geist-variable.woff2", webURL));
const brandLight = (
  await readFile(new URL("assets/branding/anonce-logo-on-light.svg", webURL))
).toString("base64");
const brandDark = (
  await readFile(new URL("assets/branding/anonce-logo-on-dark.svg", webURL))
).toString("base64");
const icons = new Map(
  await Promise.all(
    ["house", "building-2", "check-circle-2", "user-round"].map(
      async (name) => [
        name,
        (await readFile(new URL(`assets/icons/${name}.svg`, webURL))).toString(
          "base64",
        ),
      ],
    ),
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
// This prepares trusted repository fixtures, not arbitrary untrusted HTML.
// DOMParser keeps scripts inert until they have been deliberately removed.
function prepareMarkup({ html, css, brandLight, brandDark }) {
  const parsed = new DOMParser().parseFromString(html, "text/html");
  function removeScripts(root) {
    for (const script of root.querySelectorAll("script")) script.remove();
    for (const template of root.querySelectorAll("template"))
      removeScripts(template.content);
  }
  removeScripts(parsed);
  for (const link of parsed.querySelectorAll('link[rel~="stylesheet"]')) {
    const style = parsed.createElement("style");
    style.textContent = css;
    link.replaceWith(style);
  }
  for (const image of parsed.querySelectorAll("img")) {
    const source = image.getAttribute("src");
    if (source === "./assets/branding/anonce-logo-on-light.svg")
      image.setAttribute("src", `data:image/svg+xml;base64,${brandLight}`);
    if (source === "./assets/branding/anonce-logo-on-dark.svg")
      image.setAttribute("src", `data:image/svg+xml;base64,${brandDark}`);
  }
  return "<!doctype html>" + parsed.documentElement.outerHTML;
}
try {
  const page = await browser.newPage({ colorScheme: "light" });
  await mkdir(artifactDir, { recursive: true });
  await page.setViewportSize({ width: 320, height: 900 });
  const initialHTML = await readFile(new URL("index.html", webURL), "utf8");
  const prepare = (html) =>
    page.evaluate(prepareMarkup, { html, css, brandLight, brandDark });
  for (const scripts of [
    '<script>window.fixtureScriptRan = true</script><script type="module">window.fixtureScriptRan = true</script>',
    '<ScRiPt data-x=">">window.fixtureScriptRan = true</sCrIpT >',
    "<script><script>window.fixtureScriptRan = true</script></script>",
    "<template><template><script>window.fixtureScriptRan = true</script></template></template>",
    "<svg><script>window.fixtureScriptRan = true</script></svg>",
    '<script src="/must-not-load.js">',
  ]) {
    const prepared = await prepare(
      `<link rel="stylesheet" href="./styles.css"><img src="./assets/branding/anonce-logo-on-light.svg"><p id="fixture">Kept</p>${scripts}`,
    );
    await page.setContent(prepared);
    assert.equal(await page.locator("script").count(), 0);
    assert.equal(
      await page.evaluate(() => {
        function hasScript(root) {
          return (
            !!root.querySelector("script") ||
            [...root.querySelectorAll("template")].some((t) =>
              hasScript(t.content),
            )
          );
        }
        return hasScript(document);
      }),
      false,
      "scripts removed even inside nested template contents",
    );
    assert.equal(await page.evaluate(() => window.fixtureScriptRan), undefined);
    assert.equal(await page.locator("#fixture").textContent(), "Kept");
    assert.equal(await page.locator("style").textContent(), css);
    assert.equal(
      await page.locator("img").getAttribute("src"),
      `data:image/svg+xml;base64,${brandLight}`,
    );
  }
  const initialMarkup = await prepare(initialHTML);
  for (const width of [390, 1280]) {
    for (const height of [844, 1100]) {
      await page.setViewportSize({ width, height });
      for (const colorScheme of ["light", "dark"]) {
        await page.emulateMedia({ colorScheme });
        await page.setContent(initialMarkup);
        const loading = await page.evaluate(() => ({
          rootHeight: document.documentElement.getBoundingClientRect().height,
          viewportHeight: document.documentElement.clientHeight,
          scrollHeight: document.documentElement.scrollHeight,
          backgroundRepeat: getComputedStyle(document.body).backgroundRepeat,
          bootCount: document.querySelectorAll("#app .boot").length,
          navCount: document.querySelectorAll(".nav").length,
        }));
        assert.equal(
          loading.bootCount,
          1,
          "real initial boot markup is present",
        );
        assert.equal(loading.navCount, 0, "initial loading markup has no nav");
        assert.ok(
          loading.rootHeight >= loading.viewportHeight,
          `HTML background canvas ends before viewport at ${width}x${height} (${colorScheme})`,
        );
        assert.equal(
          loading.scrollHeight,
          loading.viewportHeight,
          `initial loading creates vertical overflow at ${width}x${height} (${colorScheme})`,
        );
        assert.equal(
          loading.backgroundRepeat.split(",")[0].trim(),
          "no-repeat",
          "ambient gradient must not tile",
        );
        if (width === 390 && height === 1100)
          await page.screenshot({
            path: `${artifactDir}/loading-${width}-${height}-${colorScheme}.png`,
          });
      }
    }
  }
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
    {
      email: "member.with.a.long.address@example.organization.example",
      scope: "full",
    },
    "#",
    '<div style="height:1600px">Scrollable workspace content</div>',
    "Overview",
    icon,
    (value) => String(value),
    "<a></a>",
    workspaceLabel,
  );
  await page.setContent(
    `<meta name="viewport" content="width=device-width, initial-scale=1"><style>${css.replace("url('./assets/geist-variable.woff2')", `url('data:font/woff2;base64,${font.toString("base64")}')`)}</style>${root.innerHTML.replaceAll("./assets/branding/anonce-logo-on-light.svg", `data:image/svg+xml;base64,${brandLight}`).replaceAll("./assets/branding/anonce-logo-on-dark.svg", `data:image/svg+xml;base64,${brandDark}`)}`,
  );
  assert.equal(
    await page
      .locator("body")
      .evaluate((body) => getComputedStyle(body).backgroundRepeat),
    "no-repeat, repeat",
    "ambient page gradient must not tile into horizontal bands",
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
          touchTargets: links.map((link) => {
            const { width, height } = link.getBoundingClientRect();
            return { width, height };
          }),
          linkSizes: links.map((link) => [link.scrollWidth, link.clientWidth]),
          labelFits: links.every(
            (link) => link.scrollWidth <= link.clientWidth + 1,
          ),
          activeCount: links.filter(
            (link) => link.getAttribute("aria-current") === "page",
          ).length,
          accountLabel: links
            .find((link) => link.getAttribute("href") === "#/account")
            .getAttribute("aria-label"),
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
      assert.ok(
        result.touchTargets.every(
          ({ width, height }) => width >= 43.5 && height >= 43.5,
        ),
        `navigation target below 44×44 CSS pixels at ${width}px (${colorScheme})`,
      );
      assert.equal(result.accountLabel, "Account and recovery");
      assert.equal(result.workspace, workspaceName);
      assert.equal(
        result.workspaceLabel,
        `Current workspace: ${workspaceName}`,
      );
      assert.equal(result.desktopSpacing, '" "');
      if (width <= 640) {
        assert.equal(
          await page.locator(".workspace-label").evaluate((label) => {
            const rect = label.getBoundingClientRect();
            return (
              Math.abs(rect.left + rect.width / 2 - innerWidth / 2) <= 1 &&
              rect.left >= 0 &&
              rect.right <= innerWidth
            );
          }),
          true,
          `mobile workspace pill is not centered or exceeds viewport at ${width}px`,
        );
        assert.equal(
          await page.locator(".site-header").evaluate((header) => {
            const rect = header.getBoundingClientRect();
            return (
              Math.abs(rect.left) <= 1 && Math.abs(rect.right - innerWidth) <= 1
            );
          }),
          true,
          `mobile header does not extend to viewport edges at ${width}px`,
        );
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
        if (width > 900)
          assert.equal(
            new Set(result.linkHeights).size,
            1,
            `uneven desktop navigation tiles at ${width}px (${colorScheme})`,
          );
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
      if (width === 390 && colorScheme === "light") {
        const workspaceNameNode = page.locator(".workspace-label strong");
        await workspaceNameNode.evaluate(
          (node) => (node.textContent = "Mandip"),
        );
        await page.screenshot({
          path: `${artifactDir}/workspace-centered-390-short.png`,
          fullPage: true,
        });
        await workspaceNameNode.evaluate(
          (node) =>
            (node.textContent =
              "Design workspace with a deliberately long organization name for responsive header checks"),
        );
        await page.screenshot({
          path: `${artifactDir}/workspace-centered-390-long.png`,
          fullPage: true,
        });
      }
      if (width === 320 || width === 1280)
        await page.screenshot({
          path: `${artifactDir}/navigation-${width}-${colorScheme}.png`,
          fullPage: true,
        });
    }
  }
  await page.setViewportSize({ width: 320, height: 256 });
  const shortViewport = await page.evaluate(() => ({
    width: document.documentElement.scrollWidth,
    viewport: document.documentElement.clientWidth,
    navTargets: [...document.querySelectorAll(".nav a")].map((link) => {
      const { width, height } = link.getBoundingClientRect();
      return { width, height };
    }),
  }));
  assert.equal(
    shortViewport.width,
    shortViewport.viewport,
    "horizontal overflow at 320×256 reflow viewport",
  );
  assert.ok(
    shortViewport.navTargets.every(
      ({ width, height }) => width >= 43.5 && height >= 43.5,
    ),
    "navigation target below 44×44 CSS pixels at short viewport",
  );
} finally {
  await browser.close();
}
