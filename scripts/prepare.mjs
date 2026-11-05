import { spawnSync } from "node:child_process";
import { access } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

const pathExists = async (path) => {
  try {
    await access(path);
    return true;
  } catch (cause) {
    if (
      typeof cause === "object" &&
      cause !== null &&
      "code" in cause &&
      cause.code === "ENOENT"
    )
      return false;
    throw cause;
  }
};

const sourceDependencyIsAvailable = async (path) => {
  try {
    await access(join(root, "src"));
    await access(join(root, "node_modules", path));
    return true;
  } catch (cause) {
    if (
      typeof cause === "object" &&
      cause !== null &&
      "code" in cause &&
      cause.code === "ENOENT"
    )
      return false;
    throw cause;
  }
};

// Runtime and type checking must both see the patched release dependency.
// Published installs omit source and development dependencies.
if (await sourceDependencyIsAvailable("release-please/package.json")) {
  const { applyReleasePleasePatch } =
    await import("./lib/release-proposal.mjs");
  await applyReleasePleasePatch();
}

if (
  process.env.HUSKY !== "0" &&
  (await sourceDependencyIsAvailable("husky/index.js"))
) {
  const { default: installHusky } = await import("husky");
  const message = installHusky();
  if (message.length > 0) process.stdout.write(`${message}\n`);
}

// Git and local `npx` installs run prepare without prepack; build once when needed.
if (
  (await pathExists(join(root, "src"))) &&
  !(await pathExists(join(root, "dist", "mcp", "main.js"))) &&
  (await pathExists(join(root, "node_modules", "typescript", "package.json")))
) {
  const packageManagerPath = process.env.npm_execpath;
  if (packageManagerPath !== undefined) {
    const result = spawnSync(
      process.execPath,
      [packageManagerPath, "run", "build:cached"],
      { cwd: root, stdio: "inherit" },
    );
    if (result.status !== 0)
      process.exit(result.status === null ? 1 : result.status);
  }
}
