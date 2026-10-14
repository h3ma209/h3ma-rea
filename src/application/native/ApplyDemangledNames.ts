import { z } from "zod";

import {
  AnalysisCapabilityUnavailableError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import {
  applyDemangledNamesSchema,
  isSwiftMangledName,
} from "../../domain/native/demangledNames.js";
import { demangleSwiftSchema } from "../../domain/native/nativeInspection.js";
import { enhancedInputSchemas } from "../../contracts/enhancedInputs.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import { err, ok } from "../../domain/result.js";
import { compareUnicodeCodePoints } from "../../domain/unicodeCodePointOrder.js";
import type { AnalysisOperationPort } from "../AnalysisProvider.js";
import type { EnhancedResult } from "../EnhancedToolTypes.js";

const nameItemSchema = z.array(
  z.object({
    address: z.string().min(1),
    value: z.string().min(1),
  }),
);

/** Plan or apply Swift-demangle names onto the bound symbol inventory. */
export const applyDemangledNames = async (
  analysis: AnalysisOperationPort,
  input: z.output<typeof enhancedInputSchemas.apply_demangled_names>,
  signal?: AbortSignal,
): EnhancedResult => {
  const names = await analysis.execute(
    "list_names",
    {},
    signal === undefined ? {} : { signal },
  );
  if (!names.ok) return names;
  const parsedNames = nameItemSchema.safeParse(names.value.result);
  if (!parsedNames.success)
    return err(
      new AnalysisOutputError(
        "apply_demangled_names",
        "provider returned an invalid name inventory",
        { cause: parsedNames.error },
      ),
    );
  const candidates = parsedNames.data
    .filter((item) => isSwiftMangledName(item.value))
    .filter((item) =>
      input.pattern === undefined ? true : item.value.includes(input.pattern),
    )
    .sort((left, right) => compareUnicodeCodePoints(left.address, right.address));
  const examined = candidates.slice(0, input.max_names);
  const truncated = candidates.length > examined.length;
  if (examined.length === 0)
    return ok(
      jsonValueSchema.parse(
        applyDemangledNamesSchema.parse({
          applied: false,
          plan: [],
          results: null,
          examined: 0,
          rename_count: 0,
          limitations: truncated
            ? ["Name budget max_names was reached before every mangled symbol."]
            : ["No Swift-mangled names matched the requested filter."],
        }),
      ),
    );
  const demangled = await analysis.execute(
    "demangle_swift",
    { symbols: examined.map((item) => item.value) },
    signal === undefined ? {} : { signal },
  );
  if (!demangled.ok) return demangled;
  const parsedDemangle = demangleSwiftSchema.safeParse(demangled.value.result);
  if (!parsedDemangle.success)
    return err(
      new AnalysisOutputError(
        "apply_demangled_names",
        "demangle_swift returned an invalid result",
        { cause: parsedDemangle.error },
      ),
    );
  const byInput = new Map(
    parsedDemangle.data.symbols.map((item) => [item.input, item]),
  );
  const plan = examined.map((item) => {
    const result = byInput.get(item.value);
    if (result === undefined)
      return {
        address: item.address,
        current_name: item.value,
        demangled: null,
        action: "invalid" as const,
        reason: "demangle_swift omitted this symbol",
      };
    if (result.status !== "demangled")
      return {
        address: item.address,
        current_name: item.value,
        demangled: result.output,
        action: "skip" as const,
        reason: `demangle status ${result.status}`,
      };
    if (result.output === item.value)
      return {
        address: item.address,
        current_name: item.value,
        demangled: result.output,
        action: "skip" as const,
        reason: "demangled text matches the current name",
      };
    if (
      input.pattern !== undefined &&
      !item.value.includes(input.pattern) &&
      !result.output.includes(input.pattern)
    )
      return {
        address: item.address,
        current_name: item.value,
        demangled: result.output,
        action: "skip" as const,
        reason: "demangled text does not contain the requested pattern",
      };
    return {
      address: item.address,
      current_name: item.value,
      demangled: result.output,
      action: "rename" as const,
      reason: null,
    };
  });
  const rename = plan.filter((item) => item.action === "rename");
  const limitations = [
    ...(truncated
      ? ["Name budget max_names was reached before every mangled symbol."]
      : []),
    ...parsedDemangle.data.limitations,
  ];
  if (!input.apply)
    return ok(
      jsonValueSchema.parse(
        applyDemangledNamesSchema.parse({
          applied: false,
          plan,
          results: null,
          examined: examined.length,
          rename_count: rename.length,
          limitations,
        }),
      ),
    );
  if (rename.length === 0)
    return ok(
      jsonValueSchema.parse(
        applyDemangledNamesSchema.parse({
          applied: false,
          plan,
          results: null,
          examined: examined.length,
          rename_count: 0,
          limitations: [...limitations, "No demangled names were eligible to apply."],
        }),
      ),
    );
  const applied = await analysis.execute(
    "set_addresses_names",
    {
      names: Object.fromEntries(
        rename.map((item) => [item.address, item.demangled ?? item.current_name]),
      ),
    },
    signal === undefined ? {} : { signal },
  );
  if (!applied.ok) {
    if (applied.error instanceof AnalysisCapabilityUnavailableError)
      return applied;
    return applied;
  }
  const results = z.record(z.string(), z.boolean()).safeParse(applied.value.result);
  if (!results.success)
    return err(
      new AnalysisOutputError(
        "apply_demangled_names",
        "set_addresses_names returned an invalid per-address result",
        { cause: results.error },
      ),
    );
  return ok(
    jsonValueSchema.parse(
      applyDemangledNamesSchema.parse({
        applied: true,
        plan,
        results: results.data,
        examined: examined.length,
        rename_count: rename.length,
        limitations,
      }),
    ),
  );
};
