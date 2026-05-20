import { copyFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const entries = ["background", "content", "detector", "options", "panel"];

await mkdir(join(root, "dist"), { recursive: true });

for (const entry of entries) {
  await copyFile(join(root, "src", `${entry}.ts`), join(root, "dist", `${entry}.js`));
}
