import { z } from "zod";

import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { enhancedInputSchemas } from "../../contracts/enhancedInputs.js";
import { inspectObjcSelectorRefsSchema } from "../../domain/native/objcSelectorRefs.js";
import { nativeDispatchMetadataResultSchema } from "../../domain/native/objcSwiftMetadata.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import { err, ok } from "../../domain/result.js";
import type { AnalysisOperationPort } from "../AnalysisProvider.js";
import type { EnhancedResult } from "../EnhancedToolTypes.js";
import { inspectNativeDispatch } from "./NativeDispatchMetadataInspection.js";

const normalizeAddress = (value: string): string =>
  value.trim().toLowerCase().replace(/^0x/u, "");

const xrefListSchema = z.array(z.string());

/** List static reference sites for decoded Objective-C selectors. */
export const inspectObjcSelectorRefs = async (
  analysis: AnalysisOperationPort,
  input: z.output<typeof enhancedInputSchemas.inspect_objc_selector_refs>,
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
        "inspect_objc_selector_refs",
        "dispatch metadata did not match the selector-ref contract",
        { cause: parsed.error },
      ),
    );
  const implementations =
    parsed.data.result.objc_dispatch_implementations.filter(
      (item) =>
        (input.class_name === undefined ||
          item.class_name === input.class_name) &&
        (input.selector === undefined || item.selector === input.selector),
    );
  const selectors = new Map<
    string,
    {
      selector: string;
      class_name: string | null;
      selector_address: string | null;
    }
  >();
  for (const item of implementations) {
    const key = `${item.selector}\0${item.selector_address ?? ""}`;
    if (!selectors.has(key))
      selectors.set(key, {
        selector: item.selector,
        class_name: item.class_name,
        selector_address: item.selector_address,
      });
  }
  const limitations: string[] = [];
  const refs: z.infer<typeof inspectObjcSelectorRefsSchema>["refs"] = [];
  const seen = new Set<string>();
  const addRef = (
    entry: z.infer<typeof inspectObjcSelectorRefsSchema>["refs"][number],
  ) => {
    const key = `${entry.selector}\0${entry.reference_address}`;
    if (seen.has(key)) return;
    seen.add(key);
    refs.push(entry);
  };
  const selectorEntries = [...selectors.values()].slice(0, input.max_selectors);
  const truncatedSelectors = selectors.size > selectorEntries.length;
  let resolvedStringAddresses = new Map<string, string>();
  if (selectorEntries.some((item) => item.selector_address === null)) {
    const strings = await analysis.execute(
      "list_strings",
      {},
      signal === undefined ? {} : { signal },
    );
    if (strings.ok) {
      const inventory = z
        .array(z.object({ address: z.string(), value: z.string() }))
        .safeParse(strings.value.result);
      if (inventory.success)
        resolvedStringAddresses = new Map(
          inventory.data.map((item) => [item.value, item.address]),
        );
      else limitations.push("String inventory could not be parsed for selector lookup.");
    } else limitations.push(strings.error.message);
  }
  for (const item of selectorEntries) {
    if (signal?.aborted)
      return err(new AnalysisCancelledError("inspect_objc_selector_refs"));
    const address =
      item.selector_address ??
      resolvedStringAddresses.get(item.selector) ??
      null;
    if (address === null) {
      limitations.push(
        `Selector ${item.selector} has no decoded selector address and no matching program string.`,
      );
      continue;
    }
    const xrefs = await analysis.execute(
      "xrefs",
      { address },
      signal === undefined ? {} : { signal },
    );
    if (!xrefs.ok) {
      limitations.push(xrefs.error.message);
      continue;
    }
    const sites = xrefListSchema.safeParse(xrefs.value.result);
    if (!sites.success) {
      limitations.push("Provider xrefs returned an invalid address list.");
      continue;
    }
    for (const reference of sites.data) {
      if (refs.length >= input.max_refs) break;
      let procedure: string | null = null;
      const containing = await analysis.execute(
        "resolve_containing_procedure",
        { address: reference },
        signal === undefined ? {} : { signal },
      );
      const containingResult = containing.ok
        ? z
            .object({
              found: z.literal(true),
              procedure: z.object({ address: z.string() }),
            })
            .or(z.object({ found: z.literal(false) }))
            .safeParse(containing.value.result)
        : null;
      if (containingResult?.success === true && containingResult.data.found)
        procedure = containingResult.data.procedure.address;
      addRef({
        selector: item.selector,
        class_name: item.class_name,
        selector_address: address,
        reference_address: reference,
        procedure,
        basis:
          item.selector_address === null
            ? "selector_string_xref"
            : "selector_address_xref",
      });
    }
    if (refs.length >= input.max_refs) break;
  }
  return ok(
    jsonValueSchema.parse(
      inspectObjcSelectorRefsSchema.parse({
        refs,
        examined_selectors: selectorEntries.length,
        exhaustive:
          !truncatedSelectors && refs.length < input.max_refs,
        limitations: [
          ...limitations,
          ...(truncatedSelectors
            ? ["Selector budget max_selectors was reached before every requested selector."]
            : []),
          ...(refs.length >= input.max_refs
            ? ["Reference budget max_refs was reached before every xref was recorded."]
            : []),
        ],
      }),
    ),
  );
};
