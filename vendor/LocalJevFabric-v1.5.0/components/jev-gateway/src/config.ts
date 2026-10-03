import { PROVIDERS, resolveModel, resolveProvider, resolveUrl, type ProviderId } from "./jev.js";
export type ToolRisk = "R0" | "R1" | "R2" | "R3";

export interface Config {
  /** Interface to listen on. Loopback by default: the gateway forwards credentials and must not be reachable from the LAN. */
  host: string;
  port: number;
  /** OpenAI-compatible API root, including the `/v1` suffix. */
  upstreamBaseUrl: string;
  /** Replaces the client's Authorization header upstream when set. */
  upstreamApiKey?: string;
  /** When set, clients must present this key to use the gateway. */
  routerApiKey?: string;
  /** Model used upstream once Jev has already picked the tool. */
  argsModel?: string;
  /** Who serves Jev: TypeSafe itself, or a gateway that resells it. */
  jevProvider: ProviderId;
  /** The key for that provider; the launchers ask for it when it is missing. */
  jevApiKey?: string;
  /** Endpoint the questions are posted to; the provider's own unless overridden (tests, proxies). */
  jevUrl: string;
  jevModel: string;
  jevTimeoutMs: number;
  /** Below this, Jev's tool decision is ignored and the LLM decides. */
  minConfidence: number;
  /** Per-argument certainty needed to answer without calling the LLM. */
  argMinCertainty: number;
  onNone: "force_none" | "passthrough";
  directCalls: boolean;
  /** Require an explicit fabric authority attestation before direct execution. */
  directRequireAuthority: boolean;
  /** Explicit exact-name risk policy. Unknown tools use unknownToolRisk. */
  toolRisk: Record<string, ToolRisk>;
  unknownToolRisk: ToolRisk;
  /** False starts the gateway as a plain metering proxy; the dashboard can flip it at runtime. */
  routing: boolean;
  maxStateChars: number;
  maxMessageChars: number;
  /** Opt-in: dump every routed request (decoded body, redacted headers) into this directory. */
  debugDumpDir?: string;
  /** Who this router serves ("codex", "claude"); the dashboard labels its traffic with it. */
  client: string;
  /** JSON-lines file this process's stdout is appended to, if any: the dashboard's history. */
  logFile?: string;
}

type Env = Record<string, string | undefined>;

const str = (env: Env, key: string): string | undefined => {
  const value = env[key]?.trim();
  return value ? value : undefined;
};

const num = (env: Env, key: string, fallback: number): number => {
  const raw = str(env, key);
  if (raw === undefined) return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value)) throw new Error(`${key} must be a number, got "${raw}"`);
  return value;
};

const bool = (env: Env, key: string, fallback: boolean): boolean => {
  const raw = str(env, key)?.toLowerCase();
  if (raw === undefined) return fallback;
  return raw === "1" || raw === "true" || raw === "yes" || raw === "on";
};

const RISK = new Set<ToolRisk>(["R0", "R1", "R2", "R3"]);

const risk = (env: Env, key: string, fallback: ToolRisk): ToolRisk => {
  const raw = (str(env, key) ?? fallback).toUpperCase() as ToolRisk;
  if (!RISK.has(raw)) throw new Error(`${key} must be R0, R1, R2 or R3`);
  return raw;
};

const riskMap = (env: Env): Record<string, ToolRisk> => {
  const raw = str(env, "JEV_TOOL_RISK_JSON");
  if (!raw) return {};
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw new Error("JEV_TOOL_RISK_JSON must be valid JSON"); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("JEV_TOOL_RISK_JSON must be a JSON object");
  const out: Record<string, ToolRisk> = {};
  for (const [name, value] of Object.entries(parsed)) {
    const v = String(value).toUpperCase() as ToolRisk;
    if (!RISK.has(v)) throw new Error(`JEV_TOOL_RISK_JSON[${name}] must be R0, R1, R2 or R3`);
    out[name] = v;
  }
  return out;
};

const loopback = (host: string): boolean => {
  const h = host.trim().toLowerCase().replace(/^\[|\]$/g, "");
  return h === "localhost" || h === "::1" || h === "0:0:0:0:0:0:0:1" || /^127(?:\.\d{1,3}){3}$/.test(h);
};

export function loadConfig(env: Env = process.env): Config {
  const jevProvider = resolveProvider(env);
  const jevModel = resolveModel(jevProvider, str(env, "JEV_MODEL"));
  const onNone = str(env, "JEV_ON_NONE") ?? "force_none";
  if (onNone !== "force_none" && onNone !== "passthrough") {
    throw new Error(`JEV_ON_NONE must be "force_none" or "passthrough", got "${onNone}"`);
  }
  const config: Config = {
    host: str(env, "HOST") ?? "127.0.0.1",
    port: num(env, "PORT", 8787),
    upstreamBaseUrl: (str(env, "UPSTREAM_BASE_URL") ?? "https://api.openai.com/v1").replace(/\/+$/, ""),
    upstreamApiKey: str(env, "UPSTREAM_API_KEY"),
    routerApiKey: str(env, "ROUTER_API_KEY"),
    argsModel: str(env, "ARGS_MODEL"),
    jevProvider,
    jevApiKey: str(env, PROVIDERS[jevProvider].keyEnv),
    jevUrl: resolveUrl(jevProvider, env),
    jevModel,
    jevTimeoutMs: num(env, "JEV_TIMEOUT_MS", 4000),
    minConfidence: num(env, "JEV_MIN_CONFIDENCE", 0.7),
    argMinCertainty: num(env, "JEV_ARG_MIN_CERTAINTY", 0.8),
    onNone,
    directCalls: bool(env, "JEV_DIRECT_CALLS", true),
    directRequireAuthority: bool(env, "JEV_DIRECT_REQUIRE_AUTHORITY", true),
    toolRisk: riskMap(env),
    unknownToolRisk: risk(env, "JEV_UNKNOWN_TOOL_RISK", "R1"),
    routing: bool(env, "JEV_ROUTING", true),
    maxStateChars: num(env, "JEV_MAX_STATE_CHARS", 60_000),
    maxMessageChars: num(env, "JEV_MAX_MESSAGE_CHARS", 4_000),
    debugDumpDir: str(env, "JEV_DEBUG_DUMP_DIR"),
    client: str(env, "JEV_CLIENT") ?? "standalone",
    logFile: str(env, "JEV_LOG_FILE"),
  };
  if (config.minConfidence < 0 || config.minConfidence > 1) throw new Error("JEV_MIN_CONFIDENCE must be in [0,1]");
  if (config.argMinCertainty < 0 || config.argMinCertainty > 1) throw new Error("JEV_ARG_MIN_CERTAINTY must be in [0,1]");
  if (config.jevTimeoutMs <= 0) throw new Error("JEV_TIMEOUT_MS must be > 0");
  if (config.maxStateChars < 256) throw new Error("JEV_MAX_STATE_CHARS must be >= 256");
  if (config.maxMessageChars < 64) throw new Error("JEV_MAX_MESSAGE_CHARS must be >= 64");
  if (config.routerApiKey && !config.upstreamApiKey) {
    throw new Error("ROUTER_API_KEY requires UPSTREAM_API_KEY (the client key is not valid upstream)");
  }
  if (!loopback(config.host) && !config.routerApiKey && !bool(env, "ALLOW_UNAUTHENTICATED_NETWORK", false)) {
    throw new Error("non-loopback HOST requires ROUTER_API_KEY; set ALLOW_UNAUTHENTICATED_NETWORK=true only for deliberate insecure exposure");
  }
  return config;
}
