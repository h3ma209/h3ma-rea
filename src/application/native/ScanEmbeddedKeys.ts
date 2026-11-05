import { z } from "zod";

import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import {
  inspectStringForSecrets,
  scanEmbeddedKeysResultSchema,
  type ScanEmbeddedKeysResult,
} from "../../domain/native/embeddedSecrets.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import { err, ok } from "../../domain/result.js";
import type { AnalysisOperationPort } from "../AnalysisProvider.js";
import type { EnhancedResult } from "../EnhancedToolTypes.js";

export const scanEmbeddedKeysInputSchema = z.strictObject({
  min_entropy: z.number().min(2.0).max(8.0).default(4.5),
  max_findings: z.number().int().min(1).max(5_000).default(500),
});

/** Scan binary string table and rodata for API keys, tokens, and high-entropy secrets. */
export const scanEmbeddedKeys = async (
  analysis: AnalysisOperationPort,
  input: z.output<typeof scanEmbeddedKeysInputSchema>,
  signal?: AbortSignal,
): EnhancedResult => {
  const stringsResult = await analysis.execute(
    "list_strings",
    {},
    signal === undefined ? {} : { signal },
  );

  if (!stringsResult.ok) return stringsResult;

  const stringsSchema = z.array(
    z.object({
      address: z.string(),
      value: z.string(),
    }),
  );

  const parsed = stringsSchema.safeParse(stringsResult.value.result);
  if (!parsed.success)
    return err(
      new AnalysisOutputError(
        "scan_embedded_keys",
        "Target strings output was invalid",
        { cause: parsed.error },
      ),
    );

  const findings: ScanEmbeddedKeysResult["findings"] = [];
  let highEntropyCount = 0;

  for (const item of parsed.data) {
    if (signal?.aborted)
      return err(
        new AnalysisCancelledError("scan_embedded_keys", {
          cause: signal.reason,
        }),
      );

    if (findings.length >= input.max_findings) break;

    const secret = inspectStringForSecrets(item.value, input.min_entropy);
    if (secret !== null) {
      if (secret.kind === "high_entropy_string") {
        highEntropyCount++;
      }
      findings.push({
        kind: secret.kind,
        address: item.address,
        value: item.value,
        entropy: secret.entropy,
        confidence: secret.confidence,
        description: secret.description,
      });
    }
  }

  const result: ScanEmbeddedKeysResult = {
    findings,
    total_strings_scanned: parsed.data.length,
    high_entropy_count: highEntropyCount,
    limitations:
      findings.length >= input.max_findings
        ? [`Findings capped at max_findings (${input.max_findings}) limit.`]
        : [],
  };

  return ok(jsonValueSchema.parse(result));
};
