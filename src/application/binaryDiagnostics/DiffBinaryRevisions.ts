import { z } from "zod";

import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { enhancedInputSchemas } from "../../contracts/enhancedInputs.js";
import {
  diffBinaryRevisionsResultSchema,
  type DiffBinaryRevisionsResult,
} from "../../domain/binary/binaryDiff.js";
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

export const diffBinaryRevisions = async (
  analysis: AnalysisOperationPort,
  input: z.output<typeof enhancedInputSchemas.diff_binary_revisions>,
  signal?: AbortSignal,
): EnhancedResult => {
  // 1. Get current target symbols
  const currentNamesRes = await analysis.execute(
    "list_names",
    {},
    signal === undefined ? {} : { signal },
  );
  if (!currentNamesRes.ok) return currentNamesRes;

  const currentNames = nameListSchema.safeParse(currentNamesRes.value.result);
  if (!currentNames.success)
    return err(
      new AnalysisOutputError(
        "diff_binary_revisions",
        "Current binary names could not be parsed",
        { cause: currentNames.error },
      ),
    );

  // 2. Get baseline document symbols
  const baselineNamesRes = await analysis.execute(
    "list_names",
    { document: input.baseline_document },
    signal === undefined ? {} : { signal },
  );

  const baselineMap = new Map<string, string>();
  if (baselineNamesRes.ok) {
    const parsedBaseline = nameListSchema.safeParse(
      baselineNamesRes.value.result,
    );
    if (parsedBaseline.success) {
      for (const item of parsedBaseline.data) {
        baselineMap.set(item.name, item.address);
      }
    }
  }

  const currentMap = new Map<string, string>();
  for (const item of currentNames.data) {
    currentMap.set(item.name, item.address);
  }

  const symbolDiffs: DiffBinaryRevisionsResult["symbol_differences"] = [];
  let symbolsAdded = 0;
  let symbolsRemoved = 0;

  for (const [name, addr] of currentMap.entries()) {
    if (signal?.aborted)
      return err(
        new AnalysisCancelledError("diff_binary_revisions", {
          cause: signal.reason,
        }),
      );
    if (symbolDiffs.length >= input.max_differences) break;

    if (!baselineMap.has(name)) {
      symbolsAdded++;
      symbolDiffs.push({
        name,
        change: "added",
        baseline_address: null,
        target_address: addr,
      });
    } else {
      const baseAddr = baselineMap.get(name)!;
      if (baseAddr.toLowerCase() !== addr.toLowerCase()) {
        symbolDiffs.push({
          name,
          change: "modified_address",
          baseline_address: baseAddr,
          target_address: addr,
        });
      }
    }
  }

  for (const [name, baseAddr] of baselineMap.entries()) {
    if (symbolDiffs.length >= input.max_differences) break;
    if (!currentMap.has(name)) {
      symbolsRemoved++;
      symbolDiffs.push({
        name,
        change: "removed",
        baseline_address: baseAddr,
        target_address: null,
      });
    }
  }

  const result: DiffBinaryRevisionsResult = {
    symbol_differences: symbolDiffs,
    string_differences: [],
    summary: {
      symbols_added: symbolsAdded,
      symbols_removed: symbolsRemoved,
      strings_added: 0,
      strings_removed: 0,
    },
    limitations:
      baselineMap.size === 0
        ? [
            `Baseline document '${input.baseline_document}' returned no symbols or was inaccessible.`,
          ]
        : [],
  };

  return ok(jsonValueSchema.parse(result));
};
