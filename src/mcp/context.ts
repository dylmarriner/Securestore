import type { AgentRecord } from "../services/types.js";

export interface AgentContext {
  agent: AgentRecord;
  sessionId: string;
  workspaceId: string | null;
  transport: "stdio" | "http" | "sse";
  sourceNetwork?: string;
}
