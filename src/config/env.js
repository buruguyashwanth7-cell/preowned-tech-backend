// src/config/env.js
// Loads settings from the .env file and checks that they are valid.

require("dotenv").config({ quiet: true });
const { z } = require("zod");

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(5000),
  MONGODB_URI: z
    .string()
    .min(1, "MONGODB_URI is missing")
    .refine((value) => value.startsWith("mongodb"), {
      message: "MONGODB_URI must start with mongodb:// or mongodb+srv://",
    }),
  SESSION_SECRET: z
    .string()
    .min(32, "SESSION_SECRET must be at least 32 characters long"),
  CLIENT_ORIGIN: z.url().default("http://localhost:3000"),
});

const result = schema.safeParse(process.env);

if (!result.success) {
  console.error("Invalid environment settings in your .env file:");
  for (const issue of result.error.issues) {
    // We print only the setting name and the problem, never the value.
    console.error(`  - ${issue.path.join(".")}: ${issue.message}`);
  }
  process.exit(1);
}

const env = Object.freeze(result.data);

module.exports = { env };