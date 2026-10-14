import { z } from "zod";

import { AnalysisOutputError } from "../../domain/analysisErrorCore.js";
import {
  dispatchImplementationWithoutProcedure,
  nativeDispatchImplementationMapSchema,
} from "../../domain/native/nativeDispatchImplementationMap.js";
import { nativeDispatchMetadataResultSchema } from "../../domain/native/objcSwiftMetadata.js";
import { enhancedInputSchemas } from "../../contracts/enhancedInputs.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import { err, ok } from "../../domain/result.js";
import type { AnalysisOperationPort } from "../AnalysisProvider.js";
import type { EnhancedResult } from "../EnhancedToolTypes.js";
import { inspectNativeDispatch } from "./NativeDispatchMetadataInspection.js";

const containingProcedureSchema = z.discriminatedUnion("found", [
  z.object({
    found: z.literal(true),
    query_address: z.string().optional(),
    procedure: z.object({
      address: z.string().min(1),
      name: z.string().nullable().optional(),
    }),
  }),
  z.object({
    found: z.literal(false),
    query_address: z.string().optional(),
    procedure: z.null(),
    reason: z.enum(["outside_segments", "not_in_procedure"]),
  }),
]);

/** Join decoded dispatch implementations with containing procedures. */
export const inspectNativeDispatchImplementations = async (
  analysis: AnalysisOperationPort,
  input: z.output<
    typeof enhancedInputSchemas.inspect_native_dispatch_implementations
  >,
  signal?: AbortSignal,
): EnhancedResult => {
  const metadata = await inspectNativeDispatch(
    analysis,
    input.max_records,
    signal,
  );
  if (!metadata.ok) return metadata;
  const parsed = nativeDispatchMetadataResultSchema.safeParse(metadata.value);
  if (!parsed.success)
    return err(
      new AnalysisOutputError(
        "inspect_native_dispatch_implementations",
        "dispatch metadata did not match the implementation-map contract",
        { cause: parsed.error },
      ),
    );
  const selected = parsed.data.result.objc_dispatch_implementations.filter(
    (item) =>
      (input.class_name === undefined || item.class_name === input.class_name) &&
      (input.selector === undefined || item.selector === input.selector),
  );
  const items = [];
  const limitations = new Set<string>();
  for (const implementation of selected) {
    const base = dispatchImplementationWithoutProcedure(
      implementation,
      input.resolve_procedures,
    );
    if (base.procedure !== null) {
      items.push(base);
      continue;
    }
    const address = implementation.implementation_address;
    if (address === null) {
      items.push({
        ...base,
        procedure: {
          found: false,
          address: null,
          name: null,
          reason: "implementation_unmapped",
        },
      });
      continue;
    }
    const resolved = await analysis.execute(
      "resolve_containing_procedure",
      { address },
      signal === undefined ? {} : { signal },
    );
    if (!resolved.ok) {
      limitations.add(resolved.error.message);
      items.push({
        ...base,
        procedure: {
          found: false,
          address: null,
          name: null,
          reason: "not_in_procedure",
        },
      });
      continue;
    }
    const containing = containingProcedureSchema.safeParse(resolved.value.result);
    if (!containing.success) {
      limitations.add(
        "Containing-procedure result did not match the provider contract.",
      );
      items.push({
        ...base,
        procedure: {
          found: false,
          address: null,
          name: null,
          reason: "not_in_procedure",
        },
      });
      continue;
    }
    items.push({
      ...base,
      procedure: containing.data.found
        ? {
            found: true,
            address: containing.data.procedure.address,
            name: containing.data.procedure.name ?? null,
          }
        : {
            found: false,
            address: null,
            name: null,
            reason: containing.data.reason,
          },
    });
  }
  return ok(
    jsonValueSchema.parse(
      nativeDispatchImplementationMapSchema.parse({
        items,
        total: selected.length,
        returned: items.length,
        exhaustive: parsed.data.result.coverage.every(
          (facet) =>
            facet.facet !== "objc_dispatch_implementations" ||
            facet.status === "complete",
        ),
        limitations: [...limitations],
      }),
    ),
  );
};
