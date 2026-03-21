import { defineConfig } from "drizzle-kit";

export default defineConfig({
  dbCredentials: {
    accountId: process.env.CLOUDFLARE_ACCOUNT_ID ?? "local-account",
    databaseId: process.env.CLOUDFLARE_D1_DATABASE_ID ?? "local-d1-database",
    token: process.env.CLOUDFLARE_API_TOKEN ?? "local-api-token"
  },
  dialect: "sqlite",
  driver: "d1-http",
  out: "./drizzle",
  schema: "./src/adapters/db/drizzle/schema.ts"
});
