import { getApp } from "./app.js";
import { closeDatabase } from "./config/database.js";
import { env } from "./config/env.js";
import { logger } from "./common/logger.js";

async function main() {
  const app = await getApp();
  const server = app.listen(env.PORT, () =>
    logger.info(
      { port: env.PORT, env: env.NODE_ENV },
      "LearnTest API listening",
    ),
  );
  const shutdown = (signal: string) => {
    logger.info({ signal }, "graceful shutdown");
    server.close(async () => {
      await closeDatabase();
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10000).unref();
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}
main().catch((e) => {
  logger.error({ err: (e as Error).message }, "startup failed");
  process.exit(1);
});
