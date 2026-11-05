import type { McpServer, ServerContext } from "@modelcontextprotocol/server";
import type { Logger } from "pino";

import { toolContract } from "../contracts/toolContracts.js";
import type { LldbSessionManager } from "../lldb/LldbSessionManager.js";
import { logToolExecution } from "./toolLogging.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import type { ToolResultDelivery } from "./ToolResultDelivery.js";

export type LldbToolManager = Pick<
  LldbSessionManager,
  "startSession" | "runCommand" | "closeSession"
>;

/** Register persistent LLDB session operations on the REA MCP server. */
export const registerLldbTools = (
  server: McpServer,
  manager: LldbToolManager,
  logger: Logger,
  delivery: ToolResultDelivery,
): void => {
  const start = toolContract("start_lldb_session");
  server.registerTool(
    start.name,
    toolRegistrationOptions(start),
    async (input, _context: ServerContext) => {
      const result = await logToolExecution(logger, start.name, () =>
        manager.startSession(input.binary_path, input.args),
      );
      if (result.ok)
        return delivery.toCallToolResult(
          { ok: true, value: result.value },
          start,
        );
      return delivery.toPartialErrorToolResult(
        result.error,
        start.returnsTargetContent,
      );
    },
  );

  const consoleCmd = toolContract("lldb_console");
  server.registerTool(
    consoleCmd.name,
    toolRegistrationOptions(consoleCmd),
    async (input, _context: ServerContext) => {
      const result = await logToolExecution(logger, consoleCmd.name, () =>
        manager.runCommand(input.session_id, input.command),
      );
      if (result.ok)
        return delivery.toCallToolResult(
          { ok: true, value: result.value },
          consoleCmd,
        );
      return delivery.toPartialErrorToolResult(
        result.error,
        consoleCmd.returnsTargetContent,
      );
    },
  );

  const close = toolContract("close_lldb_session");
  server.registerTool(
    close.name,
    toolRegistrationOptions(close),
    async (input) => {
      const result = await logToolExecution(logger, close.name, () =>
        manager.closeSession(input.session_id),
      );
      if (result.ok)
        return delivery.toCallToolResult(
          { ok: true, value: result.value },
          close,
        );
      return delivery.toPartialErrorToolResult(
        result.error,
        close.returnsTargetContent,
      );
    },
  );
};
