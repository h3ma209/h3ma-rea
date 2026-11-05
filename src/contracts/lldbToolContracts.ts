import { z } from "zod";

import { localPathStringSchema } from "../domain/localPath.js";
import type { ToolContract } from "./toolContractTypes.js";
import { toolContractMetadata } from "./toolEffects.js";

const sessionId = z.string().uuid();

export const LLDB_TOOL_CONTRACTS = [
  {
    name: "start_lldb_session",
    ...toolContractMetadata("start_lldb_session"),
    kind: "native-provider",
    description:
      "Start a headless LLDB debugger session on macOS/Darwin or Linux. Loads target binary and initializes an isolated debugger context.",
    inputSchema: z.strictObject({
      binary_path: localPathStringSchema.describe(
        "Absolute path to binary to debug with LLDB",
      ),
      args: z
        .array(z.string())
        .default([])
        .describe("Arguments to pass to target binary"),
    }),
    outputSchema: z.strictObject({
      session_id: sessionId,
      target_architecture: z.string(),
      status: z.enum(["ready", "failed"]),
    }),
    examples: [
      {
        title: "Start LLDB",
        input: { binary_path: "/bin/ls", args: [] },
      },
    ],
  },
  {
    name: "lldb_console",
    ...toolContractMetadata("lldb_console"),
    kind: "native-provider",
    description:
      "Execute one LLDB command (e.g. 'register read', 'bt', 'disassemble', 'p/x $rax') in the active LLDB session and return console output.",
    inputSchema: z.strictObject({
      session_id: sessionId,
      command: z.string().min(1).describe("LLDB command string to evaluate"),
    }),
    outputSchema: z.strictObject({
      session_id: sessionId,
      command: z.string(),
      output: z.string(),
      success: z.boolean(),
    }),
    examples: [
      {
        title: "Read registers",
        input: {
          session_id: "00000000-0000-4000-8000-000000000001",
          command: "register read",
        },
      },
    ],
  },
  {
    name: "close_lldb_session",
    ...toolContractMetadata("close_lldb_session"),
    kind: "native-provider",
    description:
      "Terminate the headless LLDB session and cleanup any child processes.",
    inputSchema: z.strictObject({ session_id: sessionId }),
    outputSchema: z.strictObject({
      session_id: sessionId,
      closed: z.boolean(),
    }),
    examples: [
      {
        title: "Close LLDB session",
        input: { session_id: "00000000-0000-4000-8000-000000000001" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
