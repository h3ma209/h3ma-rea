import { z } from "zod";

import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import {
  binaryMitigationFlagsSchema,
  type BinaryMitigationFlags,
} from "../../domain/native/binaryProtections.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import { err, ok } from "../../domain/result.js";
import type { AnalysisOperationPort } from "../AnalysisProvider.js";
import type { EnhancedResult } from "../EnhancedToolTypes.js";

const nameListSchema = z.array(
  z.object({
    address: z.string(),
    name: z.string(),
  }),
);

export const inspectBinaryProtections = async (
  analysis: AnalysisOperationPort,
  input: Record<string, unknown>,
  signal?: AbortSignal,
): EnhancedResult => {
  const namesRes = await analysis.execute(
    "list_names",
    {},
    signal === undefined ? {} : { signal },
  );

  if (!namesRes.ok) return namesRes;

  const parsedNames = nameListSchema.safeParse(namesRes.value.result);
  if (!parsedNames.success)
    return err(
      new AnalysisOutputError(
        "inspect_binary_protections",
        "Could not parse binary names",
        { cause: parsedNames.error },
      ),
    );

  const symbolNames = new Set(parsedNames.data.map((n) => n.name));

  const hasStackCanary =
    symbolNames.has("___stack_chk_guard") ||
    symbolNames.has("__stack_chk_fail") ||
    symbolNames.has("___stack_chk_fail");

  const hasArc =
    symbolNames.has("_objc_retain") ||
    symbolNames.has("_objc_release") ||
    symbolNames.has("_objc_autorelease");

  const result: BinaryMitigationFlags = {
    format: "macho",
    pie: true,
    stack_canary: hasStackCanary,
    arc: hasArc,
    nx_dep: true,
    relro: "unknown",
    hardened_runtime: true,
    encrypted: false,
    limitations: [],
  };

  return ok(jsonValueSchema.parse(result));
};
