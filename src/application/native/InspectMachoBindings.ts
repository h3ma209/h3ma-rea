import { z } from "zod";

import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import {
  inspectMachoBindingsResultSchema,
  type InspectMachoBindingsResult,
} from "../../domain/native/machoBindings.js";
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

export const inspectMachoBindings = async (
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

  const parsed = nameListSchema.safeParse(namesRes.value.result);
  if (!parsed.success)
    return err(
      new AnalysisOutputError(
        "inspect_macho_bindings",
        "Target symbol names could not be parsed",
        { cause: parsed.error },
      ),
    );

  const bindings: InspectMachoBindingsResult["bindings"] = [];

  for (const item of parsed.data) {
    if (signal?.aborted)
      return err(
        new AnalysisCancelledError("inspect_macho_bindings cancelled"),
      );

    if (item.name.startsWith("stub_") || item.name.includes("$stub")) {
      bindings.push({
        symbol: item.name,
        address: item.address,
        dylib: null,
        kind: "lazy",
      });
    } else if (item.name.startsWith("_OBJC_CLASS_$_")) {
      bindings.push({
        symbol: item.name,
        address: item.address,
        dylib: "libobjc.A.dylib",
        kind: "non_lazy",
      });
    }
  }

  const result: InspectMachoBindingsResult = {
    bindings,
    total_bindings: bindings.length,
    limitations: [],
  };

  return ok(jsonValueSchema.parse(result));
};
