import { z } from "zod";

import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { enhancedInputSchemas } from "../../contracts/enhancedInputs.js";
import { objcEncodingToSignature } from "../../domain/native/objcTypeEncoding.js";
import { applyObjcSignaturesSchema } from "../../domain/native/objcSignatures.js";
import { nativeDispatchImplementationMapSchema } from "../../domain/native/nativeDispatchImplementationMap.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import { err, ok } from "../../domain/result.js";
import type { AnalysisOperationPort } from "../AnalysisProvider.js";
import type { EnhancedResult } from "../EnhancedToolTypes.js";
import { inspectNativeDispatchImplementations } from "./NativeDispatchImplementationMap.js";

/** Plan or apply Objective-C method encodings as Ghidra function signatures. */
export const applyObjcSignatures = async (
  analysis: AnalysisOperationPort,
  input: z.output<typeof enhancedInputSchemas.apply_objc_signatures>,
  signal?: AbortSignal,
): EnhancedResult => {
  const metadata = await inspectNativeDispatchImplementations(
    analysis,
    {
      max_records: input.max_methods,
      resolve_procedures: true,
      ...(input.class_name === undefined ? {} : { class_name: input.class_name }),
      ...(input.selector === undefined ? {} : { selector: input.selector }),
    },
    signal,
  );
  if (!metadata.ok) return metadata;
  const parsed = nativeDispatchImplementationMapSchema.safeParse(metadata.value);
  if (!parsed.success)
    return err(
      new AnalysisOutputError(
        "apply_objc_signatures",
        "dispatch implementations did not match the signature-plan contract",
        { cause: parsed.error },
      ),
    );
  const selected = parsed.data.items.slice(0, input.max_methods);
  const truncated = parsed.data.items.length > selected.length;
  const plan = selected.map((item) => {
    const procedure =
      item.procedure?.found === true ? item.procedure.address : null;
    if (procedure === null)
      return {
        class_name: item.class_name,
        selector: item.selector,
        method_type: item.method_type,
        implementation_address: item.implementation_address,
        procedure: null,
        type_encoding: item.type_encoding,
        signature: null,
        action: "skip" as const,
        reason:
          item.procedure?.found === false
            ? item.procedure.reason
            : "containing procedure was not resolved",
      };
    if (item.type_encoding === null)
      return {
        class_name: item.class_name,
        selector: item.selector,
        method_type: item.method_type,
        implementation_address: item.implementation_address,
        procedure,
        type_encoding: null,
        signature: null,
        action: "invalid" as const,
        reason: "type encoding is absent",
      };
    const signature = objcEncodingToSignature(item.type_encoding, item.selector);
    if (signature === null)
      return {
        class_name: item.class_name,
        selector: item.selector,
        method_type: item.method_type,
        implementation_address: item.implementation_address,
        procedure,
        type_encoding: item.type_encoding,
        signature: null,
        action: "invalid" as const,
        reason: "type encoding is not a supported C signature",
      };
    return {
      class_name: item.class_name,
      selector: item.selector,
      method_type: item.method_type,
      implementation_address: item.implementation_address,
      procedure,
      type_encoding: item.type_encoding,
      signature,
      action: "apply" as const,
      reason: null,
    };
  });
  const eligible = plan.filter((item) => item.action === "apply");
  const limitations = [
    ...parsed.data.limitations,
    ...(truncated
      ? ["Method budget max_methods was reached before every decoded method."]
      : []),
  ];
  if (!input.apply || eligible.length === 0)
    return ok(
      jsonValueSchema.parse(
        applyObjcSignaturesSchema.parse({
          applied: false,
          plan,
          results: null,
          examined: selected.length,
          apply_count: eligible.length,
          limitations:
            input.apply && eligible.length === 0
              ? [...limitations, "No method encodings were eligible to apply."]
              : limitations,
        }),
      ),
    );
  const results: Record<string, boolean> = {};
  for (const item of eligible) {
    if (signal?.aborted)
      return err(new AnalysisCancelledError("apply_objc_signatures"));
    const procedure = item.procedure;
    const signature = item.signature;
    if (procedure === null || signature === null) continue;
    const applied = await analysis.execute(
      "annotate_native_function",
      { procedure, signature },
      signal === undefined ? {} : { signal },
    );
    if (!applied.ok) {
      if (applied.error._tag === "AnalysisCancelledError") return applied;
      results[procedure] = false;
      limitations.push(applied.error.message);
      continue;
    }
    results[procedure] = true;
  }
  return ok(
    jsonValueSchema.parse(
      applyObjcSignaturesSchema.parse({
        applied: true,
        plan,
        results,
        examined: selected.length,
        apply_count: eligible.length,
        limitations,
      }),
    ),
  );
};
