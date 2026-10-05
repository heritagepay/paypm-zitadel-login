import { cp, lstat, mkdir, readFile, readdir, realpath, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const applicationDirectory = fileURLToPath(new URL("../", import.meta.url));

/** Docker copies standalone to /app; keep the runner's ../migrations contract inside that tree. */
export async function packageWorkforceMigrations(appDirectory, standaloneDirectory) {
  const artifactRoot = await realpath(standaloneDirectory);
  for (const name of ["scripts", "node_modules"]) {
    const entry = await lstat(join(artifactRoot, name)).catch((error) => {
      if (error.code !== "ENOENT") throw error;
    });
    if (entry?.isSymbolicLink()) throw new Error("Workforce migration artifact directory must not be linked");
  }
  const application = JSON.parse(await readFile(join(appDirectory, "package.json"), "utf8"));
  const require = createRequire(join(appDirectory, "package.json"));
  let packageDirectory = dirname(require.resolve("postgres"));
  let installed;
  while (!installed) {
    try {
      const candidate = JSON.parse(await readFile(join(packageDirectory, "package.json"), "utf8"));
      if (candidate.name === "postgres") installed = candidate;
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    if (!installed) {
      const parent = dirname(packageDirectory);
      if (parent === packageDirectory) throw new Error("PostgreSQL runtime package unavailable");
      packageDirectory = parent;
    }
  }
  if (installed.version !== application.dependencies.postgres || Object.keys(installed.dependencies ?? {}).length)
    throw new Error("Workforce migration packaging requires the pinned standalone PostgreSQL runtime package");

  const scripts = join(standaloneDirectory, "scripts");
  const migrations = join(standaloneDirectory, "migrations");
  const runtimePackage = join(standaloneDirectory, "node_modules", "postgres");
  const names = (await readdir(join(appDirectory, "migrations"))).filter((name) => /^\d{3}_[a-z_]+\.sql$/.test(name)).sort();
  if (names.length === 0) throw new Error("Workforce migration sources unavailable");
  await mkdir(scripts, { recursive: true });
  await mkdir(dirname(runtimePackage), { recursive: true });
  await rm(migrations, { recursive: true, force: true });
  await mkdir(migrations);
  for (const name of names) await cp(join(appDirectory, "migrations", name), join(migrations, name));
  await cp(join(appDirectory, "scripts", "migrate-workforce.mjs"), join(scripts, "migrate-workforce.mjs"));
  await rm(runtimePackage, { recursive: true, force: true });
  await cp(await realpath(packageDirectory), runtimePackage, { recursive: true, dereference: true });
  const runnerRequire = createRequire(join(scripts, "migrate-workforce.mjs"));
  if (!(await realpath(runnerRequire.resolve("postgres"))).startsWith(`${artifactRoot}/node_modules/postgres/`))
    throw new Error("Workforce migration dependency escaped standalone artifact");
  // The generic scripts copy is retained for the server wrappers, but these build-only/relocated files are not entrypoints.
  await rm(join(standaloneDirectory, "migrate-workforce.mjs"), { force: true });
  await rm(join(standaloneDirectory, "package-workforce-migrations.mjs"), { force: true });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  await packageWorkforceMigrations(applicationDirectory, join(applicationDirectory, ".next", "standalone"));
