import { loadConfig } from "../config.ts";
import { createDb } from "./index.ts";
import { migrate } from "./migrate.ts";

const config = loadConfig();
const db = await createDb(config);
const applied = await migrate(db);
await db.close();
console.log(
  applied.length > 0
    ? `applied ${applied.length} migration(s): ${applied.join(", ")}`
    : "database already up to date",
);
