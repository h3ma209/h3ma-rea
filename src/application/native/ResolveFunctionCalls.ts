import { z } from "zod";

import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { enhancedInputSchemas } from "../../contracts/enhancedInputs.js";
import { functionDossierSchema } from "../../domain/hopperValues.js";
import { nativeCallTargetsSchema } from "../../domain/native/nativeInstruction.js";
import { functionCallResolutionSchema } from "../../domain/native/functionCallResolution.js";
import { nativeValueFlowSchema } from "../../domain/native/nativeValueFlow.js";
import {
  nativeDispatchMetadataResultSchema,
  objcDispatchImplementationSchema,
  swiftDispatchSlotSchema,
} from "../../domain/native/objcSwiftMetadata.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import { err, ok } from "../../domain/result.js";
import type { AnalysisOperationPort } from "../AnalysisProvider.js";
import type { EnhancedResult } from "../EnhancedToolTypes.js";
import { inspectNativeDispatch } from "./NativeDispatchMetadataInspection.js";

const normalizeAddress = (value: string): string =>
  value.trim().toLowerCase().replace(/^0x/u, "");

const OBJC_MESSAGE = /objc_msgSend/u;

type Implementation = z.infer<typeof objcDispatchImplementationSchema>;
type Slot = z.infer<typeof swiftDispatchSlotSchema>;
type Flow = z.infer<typeof nativeValueFlowSchema>;
type Dossier = z.infer<typeof functionDossierSchema>;
type CallTarget = {
  address: string;
  procedure: string | null;
  status: "direct" | "resolved-indirect" | "candidate";
  basis: "provider-reference" | "objc-metadata" | "swift-dispatch-slot";
  selector: string | null;
  class_name: string | null;
};

const callAddresses = (dossier: Dossier): string[] => {
  const flow = dossier.native_value_flow;
  const seen = new Set<string>();
  const addresses: string[] = [];
  const add = (address: string) => {
    if (seen.has(address)) return;
    seen.add(address);
    addresses.push(address);
  };
  if (flow !== null && flow.available) {
    const operations = new Map(flow.operations.map((item) => [item.id, item]));
    for (const effect of flow.effects) {
      if (effect.kind !== "direct_call" && effect.kind !== "indirect_call")
        continue;
      const operation = operations.get(effect.operation);
      if (operation !== undefined) add(operation.address);
    }
  }
  if (addresses.length === 0)
    for (const reference of dossier.outgoing_references)
      if (reference.call !== undefined) add(reference.source_address);
  return addresses;
};

const calleeName = (dossier: Dossier, address: string): string | null => {
  const named = dossier.referenced_names.find(
    (item) => item.source_address === address,
  );
  if (named !== undefined) return named.value;
  const edge = dossier.outgoing_references.find(
    (item) => item.source_address === address,
  );
  return edge?.target_procedure?.name ?? null;
};

const constantAddresses = (flow: Flow, address: string): string[] => {
  if (!flow.available) return [];
  const calls = flow.operations.filter(
    (operation) =>
      operation.address === address &&
      (operation.opcode === "CALL" || operation.opcode === "CALLIND"),
  );
  const found = new Set<string>();
  const record = (operation: (typeof calls)[number]) => {
    for (const input of operation.inputs) {
      if (input.kind !== "constant") continue;
      if (input.location !== null) found.add(normalizeAddress(input.location));
      else if (input.constant_hex !== null)
        found.add(normalizeAddress(input.constant_hex));
    }
  };
  for (const call of calls) {
    record(call);
    for (const edge of flow.def_use.filter((item) => item.use === call.id)) {
      const definition = flow.operations.find(
        (operation) => operation.id === edge.definition,
      );
      if (definition !== undefined) record(definition);
    }
  }
  return [...found];
};

const objcTargets = (
  dossier: Dossier,
  address: string,
  implementations: readonly Implementation[],
) => {
  const name = calleeName(dossier, address);
  if (name === null || !OBJC_MESSAGE.test(name)) return null;
  const flow = dossier.native_value_flow;
  const constants =
    flow === null ? [] : constantAddresses(flow, address).map(normalizeAddress);
  const strings = new Set(
    dossier.referenced_strings
      .filter((item) => item.source_address === address)
      .map((item) => item.value),
  );
  const matched = implementations.filter((item) => {
    const selectorAddress =
      item.selector_address === null
        ? null
        : normalizeAddress(item.selector_address);
    return (
      (selectorAddress !== null && constants.includes(selectorAddress)) ||
      strings.has(item.selector)
    );
  });
  const unique = new Map<string, Implementation>();
  for (const item of matched) {
    if (item.implementation_address === null) continue;
    unique.set(normalizeAddress(item.implementation_address), item);
  }
  return { matched, targets: [...unique.values()] };
};

/** Resolve every call in one procedure. Metadata joins never guess a target. */
export const resolveFunctionCalls = async (
  analysis: AnalysisOperationPort,
  input: z.output<typeof enhancedInputSchemas.resolve_function_calls>,
  signal?: AbortSignal,
): EnhancedResult => {
  const analyzed = await analysis.execute(
    "analyze_function",
    { procedure: input.procedure },
    signal === undefined ? {} : { signal },
  );
  if (!analyzed.ok) return analyzed;
  const dossier = functionDossierSchema.safeParse(analyzed.value.result);
  if (!dossier.success)
    return err(
      new AnalysisOutputError(
        "resolve_function_calls",
        "analyze_function returned an invalid dossier",
        { cause: dossier.error },
      ),
    );
  const limitations: string[] = [];
  let implementations: Implementation[] = [];
  let slots: Slot[] = [];
  const metadata = await inspectNativeDispatch(
    analysis,
    input.max_records,
    signal,
  );
  if (!metadata.ok) {
    if (!(metadata.error instanceof AnalysisCapabilityUnavailableError))
      return metadata;
    limitations.push(metadata.error.message);
  } else {
    const parsed = nativeDispatchMetadataResultSchema.safeParse(metadata.value);
    if (!parsed.success)
      return err(
        new AnalysisOutputError(
          "resolve_function_calls",
          "dispatch metadata did not match the call-resolution contract",
          { cause: parsed.error },
        ),
      );
    implementations = parsed.data.result.objc_dispatch_implementations;
    slots = parsed.data.result.swift_dispatch_slots;
  }
  const addresses = callAddresses(dossier.data);
  const examined = addresses.slice(0, input.max_sites);
  const sites = [];
  for (const address of examined) {
    if (signal?.aborted)
      return err(new AnalysisCancelledError("resolve_function_calls"));
    const resolved = await analysis.execute(
      "resolve_native_call_targets",
      { address },
      signal === undefined ? {} : { signal },
    );
    if (!resolved.ok) {
      if (resolved.error._tag === "AnalysisCancelledError") return resolved;
      sites.push({
        address,
        status: "unavailable" as const,
        mechanism: "unavailable" as const,
        basis: "provider-reference" as const,
        targets: [],
        limitations: [resolved.error.message],
      });
      continue;
    }
    const provider = nativeCallTargetsSchema.safeParse(resolved.value.result);
    if (!provider.success)
      return err(
        new AnalysisOutputError(
          "resolve_function_calls",
          "resolve_native_call_targets returned an invalid result",
          { cause: provider.error },
        ),
      );
    let status = provider.data.status;
    let mechanism = provider.data.mechanism;
    let basis: "provider-reference" | "objc-metadata" | "swift-dispatch-slot" =
      "provider-reference";
    let targets: CallTarget[] = provider.data.targets.map((target) => ({
      address: target.address,
      procedure: target.procedure,
      status: target.status,
      basis: "provider-reference" as const,
      selector: null,
      class_name: null,
    }));
    const siteLimitations = [...provider.data.limitations];
    if (status === "unresolved" || status === "ambiguous") {
      const objc = objcTargets(dossier.data, address, implementations);
      if (objc !== null && objc.targets.length === 1) {
        const implementation = objc.targets[0];
        if (implementation !== undefined && implementation.implementation_address !== null) {
          status = "resolved-indirect";
          mechanism = "computed";
          basis = "objc-metadata";
          targets = [
            {
              address: implementation.implementation_address,
              procedure: implementation.implementation_address,
              status: "resolved-indirect",
              basis: "objc-metadata",
              selector: implementation.selector,
              class_name: implementation.class_name,
            },
          ];
        }
      } else if (objc !== null && objc.targets.length > 1) {
        status = "ambiguous";
        mechanism = "computed";
        basis = "objc-metadata";
        targets = objc.targets.flatMap((implementation) =>
          implementation.implementation_address === null
            ? []
            : [
                {
                  address: implementation.implementation_address,
                  procedure: implementation.implementation_address,
                  status: "candidate" as const,
                  basis: "objc-metadata" as const,
                  selector: implementation.selector,
                  class_name: implementation.class_name,
                },
              ],
        );
      } else if (objc !== null)
        siteLimitations.push(
          "Objective-C selector matched no implementation address",
        );
    }
    if (status === "direct" || status === "resolved-indirect") {
      const labeled = targets.map((target) => {
        const slot = slots.find(
          (item) =>
            item.implementation_address !== null &&
            normalizeAddress(item.implementation_address) ===
              normalizeAddress(target.address),
        );
        return slot === undefined
          ? target
          : { ...target, basis: "swift-dispatch-slot" as const };
      });
      if (labeled.some((target) => target.basis === "swift-dispatch-slot")) {
        targets = labeled;
        if (basis === "provider-reference") basis = "swift-dispatch-slot";
      }
    }
    sites.push({
      address,
      status,
      mechanism,
      basis,
      targets,
      limitations: siteLimitations,
    });
  }
  return ok(
    jsonValueSchema.parse(
      functionCallResolutionSchema.parse({
        procedure: dossier.data.procedure.address,
        sites,
        examined: examined.length,
        exhaustive: examined.length === addresses.length,
        limitations,
      }),
    ),
  );
};
