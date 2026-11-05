import { z } from "zod";

import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import {
  detectCryptoPrimitivesResultSchema,
  type DetectCryptoPrimitivesResult,
} from "../../domain/native/cryptoDetection.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import { err, ok } from "../../domain/result.js";
import type { AnalysisOperationPort } from "../AnalysisProvider.js";
import type { EnhancedResult } from "../EnhancedToolTypes.js";

const stringListSchema = z.array(
  z.object({
    address: z.string(),
    value: z.string(),
  }),
);

export const detectCryptoPrimitives = async (
  analysis: AnalysisOperationPort,
  input: Record<string, unknown>,
  signal?: AbortSignal,
): EnhancedResult => {
  const stringsRes = await analysis.execute(
    "list_strings",
    {},
    signal === undefined ? {} : { signal },
  );

  if (!stringsRes.ok) return stringsRes;

  const parsed = stringListSchema.safeParse(stringsRes.value.result);
  if (!parsed.success)
    return err(
      new AnalysisOutputError(
        "detect_crypto_primitives",
        "Target strings output was invalid",
        { cause: parsed.error },
      ),
    );

  const primitives: DetectCryptoPrimitivesResult["primitives"] = [];

  for (const item of parsed.data) {
    if (signal?.aborted)
      return err(
        new AnalysisCancelledError("detect_crypto_primitives", {
          cause: signal.reason,
        }),
      );

    const val = item.value.toLowerCase();
    if (val.includes("expand 32-byte k")) {
      primitives.push({
        algorithm: "ChaCha20",
        address: item.address,
        description: "ChaCha20 constant string 'expand 32-byte k'",
        confidence: "high",
      });
    } else if (val.includes("sha256") || val.includes("sha-256")) {
      primitives.push({
        algorithm: "SHA256",
        address: item.address,
        description: "SHA-256 cryptographic identifier",
        confidence: "medium",
      });
    } else if (
      val.includes("aes-") ||
      val.includes("aes128") ||
      val.includes("aes256")
    ) {
      primitives.push({
        algorithm: "AES",
        address: item.address,
        description: "AES cipher suite identifier",
        confidence: "medium",
      });
    }
  }

  const result: DetectCryptoPrimitivesResult = {
    primitives,
    total_constants_found: primitives.length,
    limitations: [],
  };

  return ok(jsonValueSchema.parse(result));
};
