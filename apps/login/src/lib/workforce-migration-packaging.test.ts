// @vitest-environment node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { packageWorkforceMigrations } from "../../scripts/package-workforce-migrations.mjs";

const application = fileURLToPath(new URL("../../", import.meta.url));
const directories: string[] = [];
async function directory() {
  const result = await mkdtemp(join(tmpdir(), "paypm-login-migration-package-"));
  directories.push(result);
  return result;
}
afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});
function execute(artifact: string, configured = false) {
  return spawnSync("bun", [join(artifact, "scripts", "migrate-workforce.mjs")], {
    cwd: artifact,
    encoding: "utf8",
    // Server-only ambient fields do not apply to this deliberately isolated child environment.
    env: Object.assign(Object.create(null) as NodeJS.ProcessEnv, {
      PATH: process.env.PATH,
      ...(configured ? { PAYPM_WORKFORCE_MIGRATION_DATABASE_URL: "postgres://package-test@127.0.0.1/never-connect" } : {}),
    }),
  });
}
async function fixture(dependencyVersion = "3.4.7") {
  const root = await directory();
  const source = join(root, "source");
  const artifact = join(root, "artifact");
  const dependency = join(source, "node_modules", "postgres");
  await mkdir(dependency, { recursive: true });
  await mkdir(artifact);
  await cp(join(application, "migrations"), join(source, "migrations"), { recursive: true });
  await mkdir(join(source, "scripts"));
  await cp(join(application, "scripts", "migrate-workforce.mjs"), join(source, "scripts", "migrate-workforce.mjs"));
  await writeFile(join(source, "package.json"), JSON.stringify({ dependencies: { postgres: "3.4.7" } }));
  await writeFile(
    join(dependency, "package.json"),
    JSON.stringify({ name: "postgres", version: dependencyVersion, type: "module", main: "index.js" }),
  );
  await writeFile(
    join(dependency, "index.js"),
    `import { createHash } from "node:crypto";
export default function postgres() {
  const applied = [], sources = [];
  const sql = async (strings, ...values) => {
    if (strings[0].startsWith("INSERT INTO login_workforce_migrations")) applied.push(values);
    return [];
  };
  sql.begin = async (callback) => callback(sql);
  sql.unsafe = async (source) => sources.push(createHash("sha256").update(source).digest("hex"));
  sql.end = async () => console.log(JSON.stringify({ applied, sources }));
  return sql;
}
`,
  );
  return { source, artifact };
}

describe("workforce migration standalone artifact", () => {
  it("contains byte-identical SQL and the actual pinned PostgreSQL package resolvable from the final runner path", async () => {
    const artifact = await directory();
    await packageWorkforceMigrations(application, artifact);
    const names = (await readdir(join(application, "migrations"))).filter((name) => name.endsWith(".sql")).sort();
    expect((await readdir(join(artifact, "migrations"))).sort()).toEqual(names);
    for (const name of names)
      expect(await readFile(join(artifact, "migrations", name))).toEqual(
        await readFile(join(application, "migrations", name)),
      );
    const dependency = JSON.parse(await readFile(join(artifact, "node_modules", "postgres", "package.json"), "utf8"));
    expect(dependency.version).toBe("3.4.7");
    const result = execute(artifact);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Workforce migration credentials unavailable");
    expect(result.stderr).not.toContain("Cannot find");
  });

  it("executes the copied runner against all seven packaged files using only a fixture PostgreSQL adapter", async () => {
    const { source, artifact } = await fixture();
    await packageWorkforceMigrations(source, artifact);
    const result = execute(artifact, true);
    expect(result.status).toBe(0);
    const output = JSON.parse(result.stdout.trim().split("\n").at(-1)!);
    const names = (await readdir(join(source, "migrations"))).filter((name) => name.endsWith(".sql")).sort();
    const checksums = await Promise.all(
      names.map(async (name) =>
        createHash("sha256")
          .update(await readFile(join(source, "migrations", name)))
          .digest("hex"),
      ),
    );
    expect(output.applied).toEqual(names.map((name, index) => [name.slice(0, -4), checksums[index]]));
    expect(output.sources).toEqual(checksums);
    expect(output.applied).toHaveLength(7);
  });

  it("rejects dependency drift instead of publishing an unqualified runtime package", async () => {
    const { source, artifact } = await fixture("3.4.8");
    await expect(packageWorkforceMigrations(source, artifact)).rejects.toThrow(
      "pinned standalone PostgreSQL runtime package",
    );
    expect(await readdir(artifact)).toEqual([]);
  });

  it("rejects generated external directory links before writing into a foreign dependency or script tree", async () => {
    for (const name of ["node_modules", "scripts"]) {
      const { source, artifact } = await fixture();
      const foreign = await directory();
      await writeFile(join(foreign, "preserved"), "unchanged");
      await symlink(foreign, join(artifact, name));
      await expect(packageWorkforceMigrations(source, artifact)).rejects.toThrow("artifact directory must not be linked");
      expect(await readdir(foreign)).toEqual(["preserved"]);
      expect(await readFile(join(foreign, "preserved"), "utf8")).toBe("unchanged");
      expect(await readdir(artifact)).toEqual([name]);
    }
  });

  it("wires migration packaging into the existing standalone build that Docker copies to /app", async () => {
    const manifest = JSON.parse(await readFile(join(application, "package.json"), "utf8"));
    expect(manifest.scripts.build).toContain(
      "cp -r public scripts/* .next/standalone/ && node scripts/package-workforce-migrations.mjs",
    );
    expect(await readFile(join(application, "Dockerfile"), "utf8")).toContain(
      "COPY --chown=nextjs:nodejs .next/standalone ./",
    );
  });
});
