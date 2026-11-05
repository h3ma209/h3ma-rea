import { spawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { err, ok, type Result } from "../domain/result.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";

interface ActiveLldbSession {
  readonly id: string;
  readonly process: ChildProcess;
  readonly binaryPath: string;
}

export class LldbSessionManager {
  readonly #sessions = new Map<string, ActiveLldbSession>();

  async startSession(
    binaryPath: string,
    args: readonly string[] = [],
  ): Promise<
    Result<
      { session_id: string; target_architecture: string; status: "ready" },
      AnalysisError
    >
  > {
    const id = randomUUID();
    try {
      const child = spawn(
        "/usr/bin/lldb",
        ["--no-lldbinit", "--batch", "-o", `target create "${binaryPath}"`],
        { stdio: ["pipe", "pipe", "pipe"] },
      );

      this.#sessions.set(id, { id, process: child, binaryPath });

      return ok({
        session_id: id,
        target_architecture: process.arch,
        status: "ready",
      });
    } catch (cause: unknown) {
      return err(
        new AnalysisOutputError(
          "start_lldb_session",
          "Failed to launch LLDB process",
          {
            cause,
          },
        ),
      );
    }
  }

  async runCommand(
    sessionId: string,
    command: string,
  ): Promise<
    Result<
      { session_id: string; command: string; output: string; success: boolean },
      AnalysisError
    >
  > {
    const session = this.#sessions.get(sessionId);
    if (!session) {
      return err(
        new AnalysisInputError("lldb_console", undefined, [
          {
            path: ["session_id"],
            reason: "invalid_value",
            message: `No active LLDB session found for ID ${sessionId}`,
          },
        ]),
      );
    }

    return new Promise((resolve) => {
      const child = spawn(
        "/usr/bin/lldb",
        [
          "--no-lldbinit",
          "--batch",
          "-o",
          `target create "${session.binaryPath}"`,
          "-o",
          command,
        ],
        { stdio: ["pipe", "pipe", "pipe"] },
      );

      let output = "";
      child.stdout?.on("data", (chunk: Buffer) => {
        output += chunk.toString("utf8");
      });
      child.stderr?.on("data", (chunk: Buffer) => {
        output += chunk.toString("utf8");
      });

      child.on("close", (code) => {
        resolve(
          ok({
            session_id: sessionId,
            command,
            output: output.trim(),
            success: code === 0,
          }),
        );
      });

      child.on("error", (cause) => {
        resolve(
          err(
            new AnalysisOutputError("lldb_console", "LLDB command failed", {
              cause,
            }),
          ),
        );
      });
    });
  }

  async closeSession(
    sessionId: string,
  ): Promise<Result<{ session_id: string; closed: boolean }, AnalysisError>> {
    const session = this.#sessions.get(sessionId);
    if (session) {
      try {
        session.process.kill();
      } catch {
        // already closed
      }
      this.#sessions.delete(sessionId);
    }
    return ok({ session_id: sessionId, closed: true });
  }
}
