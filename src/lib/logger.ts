import { redactSecrets } from "./secrets";

type Fields = Record<string, unknown>;

/**
 * Structured JSON logger. Every line is redacted against all known secret
 * values before being written, so a buggy call site cannot leak a key.
 */
function write(level: "info" | "warn" | "error", msg: string, fields: Fields) {
  const line = JSON.stringify({ level, msg, ts: new Date().toISOString(), ...fields });
  const safe = redactSecrets(line);
  if (level === "error") console.error(safe);
  else if (level === "warn") console.warn(safe);
  else console.log(safe);
}

export const logger = {
  info: (msg: string, fields: Fields = {}) => write("info", msg, fields),
  warn: (msg: string, fields: Fields = {}) => write("warn", msg, fields),
  error: (msg: string, fields: Fields = {}) => write("error", msg, fields)
};
