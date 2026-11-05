import { z } from "zod";

import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { enhancedInputSchemas } from "../../contracts/enhancedInputs.js";
import {
  classifySwiftConcurrencySymbol,
  inspectSwiftConcurrencyResultSchema,
  type InspectSwiftConcurrencyResult,
} from "../../domain/native/swiftConcurrency.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import { err, ok } from "../../domain/result.js";
import type { AnalysisOperationPort } from "../AnalysisProvider.js";
import type { EnhancedResult } from "../EnhancedToolTypes.js";

const procedureListSchema = z.array(
  z.object({
    address: z.string(),
    name: z.string(),
  }),
);

export const inspectSwiftConcurrency = async (
  analysis: AnalysisOperationPort,
  input: z.output<typeof enhancedInputSchemas.inspect_swift_concurrency>,
  signal?: AbortSignal,
): EnhancedResult => {
  const procsResult = await analysis.execute(
    "list_procedures",
    {},
    signal === undefined ? {} : { signal },
  );

  if (!procsResult.ok) return procsResult;

  const parsed = procedureListSchema.safeParse(procsResult.value.result);
  if (!parsed.success)
    return err(
      new AnalysisOutputError(
        "inspect_swift_concurrency",
        "Target procedure list was invalid",
        { cause: parsed.error },
      ),
    );

  const actors = new Map<
    string,
    {
      name: string;
      mangled_name: string;
      address: string | null;
      isolated_methods: string[];
    }
  >();
  const asyncFunctions: InspectSwiftConcurrencyResult["async_functions"] = [];
  let totalConcurrencySymbols = 0;

  for (const item of parsed.data) {
    if (signal?.aborted)
      return err(
        new AnalysisCancelledError("inspect_swift_concurrency", {
          cause: signal.reason,
        }),
      );

    const classification = classifySwiftConcurrencySymbol(item.name);
    if (!classification.isConcurrency) continue;

    totalConcurrencySymbols++;

    let demangledName = item.name;
    const demangleResult = await analysis.execute(
      "demangle_swift",
      { name: item.name },
      signal === undefined ? {} : { signal },
    );
    if (demangleResult.ok && typeof demangleResult.value.result === "string") {
      demangledName = demangleResult.value.result;
    }

    if (classification.kind === "actor") {
      if (!actors.has(demangledName)) {
        actors.set(demangledName, {
          name: demangledName,
          mangled_name: item.name,
          address: item.address,
          isolated_methods: [],
        });
      }
    } else {
      asyncFunctions.push({
        name: demangledName,
        mangled_name: item.name,
        entry_address: item.address,
        continuation_points: [],
        kind: classification.kind ?? "unknown",
      });
    }

    if (totalConcurrencySymbols >= input.max_records) break;
  }

  const result: InspectSwiftConcurrencyResult = {
    actors: [...actors.values()],
    async_functions: asyncFunctions,
    total_concurrency_symbols: totalConcurrencySymbols,
    limitations:
      totalConcurrencySymbols >= input.max_records
        ? [`Inspection capped at max_records (${input.max_records}) limit.`]
        : [],
  };

  return ok(jsonValueSchema.parse(result));
};
