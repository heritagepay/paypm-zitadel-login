// @vitest-environment node
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, readlink, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import nextConfig from "../../next.config.mjs";

const require = createRequire(import.meta.url);
// Exercise the pinned Next copier/glob rather than a replacement packaging implementation.
const { copyTracedFiles } = require("next/dist/build/utils");
const glob = require("next/dist/compiled/glob");
const directories: string[] = [];
const packages = [
  {
    name: "@colors/colors",
    version: "1.5.0",
    store: "@colors+colors@1.5.0",
    target: "../../@colors+colors@1.5.0/node_modules/@colors/colors",
  },
  { name: "has-flag", version: "3.0.0", store: "has-flag@3.0.0", target: "../has-flag@3.0.0/node_modules/has-flag" },
] as const;
const runtimePackages = [
  { name: "@colors/colors", version: "1.6.0", store: "@colors+colors@1.6.0" },
  { name: "has-flag", version: "4.0.0", store: "has-flag@4.0.0" },
] as const;
afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});
const hash = (data: Buffer) => createHash("sha256").update(data).digest("hex");
async function fixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), "paypm-login-standalone-tracing-")));
  directories.push(root);
  const app = join(root, "apps/login"),
    dist = join(app, ".next");
  const routeTrace = join(dist, "server/app/login/route.js.nft.json");
  await mkdir(dirname(routeTrace), { recursive: true });
  await writeFile(join(app, "package.json"), JSON.stringify({ name: "synthetic-login", type: "module" }));
  const files: string[] = [];
  for (const pkg of [...packages, ...runtimePackages]) {
    const folder = join(root, "node_modules/.pnpm", pkg.store, "node_modules", pkg.name);
    await mkdir(join(folder, "lib"), { recursive: true });
    await writeFile(
      join(folder, "package.json"),
      JSON.stringify({ name: pkg.name, version: pkg.version, main: "lib/index.cjs" }),
    );
    await writeFile(join(folder, "lib/index.cjs"), `module.exports = ${JSON.stringify(pkg.name + "@" + pkg.version)};\n`);
    if (runtimePackages.some((entry) => entry.version === pkg.version))
      files.push(...["package.json", "lib/index.cjs"].map((name) => relative(dist, join(folder, name))));
  }
  for (const pkg of packages) {
    const link = join(root, "node_modules/.pnpm/node_modules", pkg.name);
    await mkdir(dirname(link), { recursive: true });
    await symlink(pkg.target, link);
    files.push(relative(dist, link));
  }
  const unrelated = join(root, "node_modules/.pnpm/unowned@9.0.0/node_modules/unowned/preserved.txt");
  await mkdir(dirname(unrelated), { recursive: true });
  await writeFile(unrelated, "unrelated synthetic package payload");
  await writeFile(join(dist, "next-server.js.nft.json"), JSON.stringify({ version: 1, files }));
  await writeFile(routeTrace, JSON.stringify({ version: 1, files: [] }));
  return { root, app, dist, routeTrace, unrelated, standalone: join(dist, "standalone") };
}
async function copy(f: Awaited<ReturnType<typeof fixture>>) {
  await copyTracedFiles(
    f.app,
    f.dist,
    [],
    ["login/route"],
    f.root,
    {},
    { middleware: {}, functions: {} },
    false,
    false,
    new Set(),
  );
}
async function includes(f: Awaited<ReturnType<typeof fixture>>) {
  const files: string[] = [];
  for (const pattern of nextConfig.outputFileTracingIncludes!["/*"]!) {
    const matched = await new Promise<string[]>((resolve, reject) =>
      glob(pattern, { cwd: f.app, nodir: true, dot: true }, (error: Error | null, paths: string[]) =>
        error ? reject(error) : resolve(paths),
      ),
    );
    expect(matched.length).toBeGreaterThan(0);
    files.push(...matched.map((name) => relative(dirname(f.routeTrace), join(f.app, name))));
  }
  await writeFile(f.routeTrace, JSON.stringify({ version: 1, files }));
}

describe("locked pnpm hoisted standalone dependency closure", () => {
  it("keeps exact locked target versions without a root-wide trace or collector replacement", () => {
    expect(require("next/package.json").version).toBe("16.2.6");
    expect(nextConfig.outputFileTracingIncludes).toEqual({
      "/*": packages.map((pkg) => `../../node_modules/.pnpm/${pkg.store}/node_modules/${pkg.name}/**/*`),
    });
    expect(nextConfig.outputFileTracingRoot).toEqual(nextConfig.turbopack!.root);
    expect(nextConfig.outputFileTracingExcludes).toBeUndefined();
    expect(nextConfig.serverExternalPackages).toContain("winston");
  });

  it("reproduces both retained hoisted dangling links with the actual Next standalone copier", async () => {
    const f = await fixture();
    await copy(f);
    for (const pkg of packages) {
      const link = join(f.standalone, "node_modules/.pnpm/node_modules", pkg.name);
      expect(await readlink(link)).toBe(pkg.target);
      await expect(realpath(link)).rejects.toMatchObject({ code: "ENOENT" });
    }
    for (const pkg of runtimePackages)
      expect(
        await readFile(join(f.standalone, "node_modules/.pnpm", pkg.store, "node_modules", pkg.name, "lib/index.cjs")),
      ).toEqual(await readFile(join(f.root, "node_modules/.pnpm", pkg.store, "node_modules", pkg.name, "lib/index.cjs")));
  });

  it("closes both links with byte-identical targets, preserving runtime versions and excluding unrelated payloads", async () => {
    const f = await fixture();
    await includes(f);
    await copy(f);
    const standaloneRequire = createRequire(join(f.standalone, "node_modules/.pnpm/node_modules/probe.cjs"));
    for (const pkg of packages) {
      const link = join(f.standalone, "node_modules/.pnpm/node_modules", pkg.name);
      expect(await readlink(link)).toBe(pkg.target);
      expect(await realpath(link)).toBe(join(f.standalone, "node_modules/.pnpm", pkg.store, "node_modules", pkg.name));
      expect(standaloneRequire(pkg.name)).toBe(pkg.name + "@" + pkg.version);
    }
    for (const pkg of [...packages, ...runtimePackages])
      for (const name of ["package.json", "lib/index.cjs"])
        expect(
          hash(await readFile(join(f.standalone, "node_modules/.pnpm", pkg.store, "node_modules", pkg.name, name))),
        ).toBe(hash(await readFile(join(f.root, "node_modules/.pnpm", pkg.store, "node_modules", pkg.name, name))));
    await expect(readFile(join(f.standalone, relative(f.root, f.unrelated)))).rejects.toMatchObject({ code: "ENOENT" });
  });
});
