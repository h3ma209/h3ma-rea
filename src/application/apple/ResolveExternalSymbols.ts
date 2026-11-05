import { existsSync } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { z } from "zod";

import { localPathStringSchema } from "../../domain/localPath.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { AnalysisOperationPort } from "../AnalysisProvider.js";
import type { EnhancedResult } from "../EnhancedToolTypes.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";

const execFileAsync = promisify(execFile);

export const resolveExternalSymbolsInputSchema = z.strictObject({
  binary_path: localPathStringSchema.describe("Target binary executable path"),
});

export const resolveExternalSymbolsResultSchema = z.strictObject({
  binary_path: z.string(),
  dsym_found: z.boolean(),
  dsym_path: z.string().nullable(),
  uuid: z.string().nullable(),
  limitations: z.array(z.string()),
});

export type ResolveExternalSymbolsResult = z.infer<
  typeof resolveExternalSymbolsResultSchema
>;

/** Query dwarfdump and mdfind for matching macOS .dSYM bundles. */
export const resolveExternalSymbols = async (
  analysis: AnalysisOperationPort,
  input: z.output<typeof resolveExternalSymbolsInputSchema>,
  signal?: AbortSignal,
): EnhancedResult => {
  if (process.platform !== "darwin") {
    return ok(
      jsonValueSchema.parse({
        binary_path: input.binary_path,
        dsym_found: false,
        dsym_path: null,
        uuid: null,
        limitations: ["dSYM resolution is only supported on macOS hosts."],
      }),
    );
  }

  try {
    const { stdout: uuidOutput } = await execFileAsync("dwarfdump", [
      "-u",
      input.binary_path,
    ]);
    const match = /UUID:\s+([A-F0-9-]+)/i.exec(uuidOutput);
    const uuid = match ? match[1] : null;

    if (!uuid) {
      return ok(
        jsonValueSchema.parse({
          binary_path: input.binary_path,
          dsym_found: false,
          dsym_path: null,
          uuid: null,
          limitations: ["No DWARF UUID could be extracted from target binary."],
        }),
      );
    }

    const { stdout: mdfindOutput } = await execFileAsync("mdfind", [
      `com_apple_xcode_dsym_uuids == "${uuid}"`,
    ]);
    const paths = mdfindOutput.trim().split("\n").filter(Boolean);
    const dsymPath = paths.length > 0 ? paths[0] : null;

    return ok(
      jsonValueSchema.parse({
        binary_path: input.binary_path,
        dsym_found: dsymPath !== null,
        dsym_path: dsymPath,
        uuid,
        limitations: [],
      }),
    );
  } catch (cause: unknown) {
    return ok(
      jsonValueSchema.parse({
        binary_path: input.binary_path,
        dsym_found: false,
        dsym_path: null,
        uuid: null,
        limitations: [`Spotlight or dwarfdump lookup failed: ${String(cause)}`],
      }),
    );
  }
};
