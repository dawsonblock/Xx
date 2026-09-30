import type { Config } from "./config.js";
import type { Json, RouterInput, Turn } from "./types.js";

export type Limits = Pick<Config, "maxStateChars" | "maxMessageChars">;

/** Keep the head and tail of long text; the middle is what matters least for routing. */
export function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  const marker = " …[truncated]… ";
  const keep = Math.max(0, max - marker.length);
  const head = Math.ceil(keep * 0.6);
  return text.slice(0, head) + marker + text.slice(text.length - (keep - head));
}

/** Jev is text-only: flatten content parts and leave a placeholder for anything else. */
export function textOf(content: unknown): string {
  if (content == null) return "";
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return JSON.stringify(content);
  return content
    .map((part: { type?: string; text?: unknown }) =>
      typeof part?.text === "string" ? part.text : `[${part?.type ?? "attachment"}]`,
    )
    .join("\n");
}

/**
 * Jev state: the content the questions are asked about.
 * The newest turns are kept when the conversation exceeds the state budget.
 */
export function buildState(input: Pick<RouterInput, "system" | "turns">, limits: Limits): { [key: string]: Json } {
  const systemText = truncate(input.system, limits.maxMessageChars);
  let budget = Math.max(0, limits.maxStateChars - systemText.length - 128);
  const conversation: Turn[] = [];
  for (let i = input.turns.length - 1; i >= 0; i--) {
    const turn = input.turns[i]!;
    const encoded = JSON.stringify(turn);
    if (encoded.length <= budget) {
      conversation.unshift(turn);
      budget -= encoded.length;
      continue;
    }
    // Preserve some evidence from an oversized newest turn instead of silently exceeding the cap.
    // Older oversized turns are simply omitted once newer context has consumed the budget.
    if (conversation.length === 0 && budget > 40) {
      const role = typeof turn.role === "string" ? turn.role : "unknown";
      const shell = JSON.stringify({ role, text: "" }).length;
      const room = Math.max(0, budget - shell - 4);
      const clipped: Turn = { role, text: truncate(encoded, room) };
      if (JSON.stringify(clipped).length <= budget) conversation.unshift(clipped);
    }
    break;
  }
  const omitted = input.turns.length - conversation.length;
  return {
    ...(systemText ? { assistant_instructions: systemText } : {}),
    ...(omitted ? { earlier_turns_omitted: omitted } : {}),
    conversation,
  };
}
