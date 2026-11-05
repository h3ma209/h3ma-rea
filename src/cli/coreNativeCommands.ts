import { projectCliAnalysisResult } from "./projectCliAnalysisResult.js";
import { nativeDispatchMetadataInputSchema } from "../domain/native/objcSwiftMetadata.js";
import { nativeValueTraceInputSchema } from "../domain/native/nativeValueTrace.js";
import { z } from "incur";
import {
  bytePatternFields,
  validateBytePattern,
  MAX_BYTE_SEARCH_MATCHES,
} from "../domain/native/bytePattern.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import { localPathStringSchema } from "../domain/localPath.js";

import {
  addressOrProcedureGuidance,
  equalSelectorGuidance,
  resolveCliAnalysisSelector,
} from "./analysisSelector.js";

import type { DirectAnalysis } from "../composition/directAnalysis.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import type { Logger } from "pino";
import {
  directAnalysisOptionsFromCli,
  nativeOpenOptionFields,
  snapshotSelectionOption,
} from "./options.js";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";
import {
  analysisEvidenceDeliveryOptions,
  cliEvidenceDeliveryInputError,
  cliEvidenceSourceClosure,
  publishCliAnalysisEvidence,
} from "./analysisEvidenceDelivery.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { AnalysisOutputError } from "../domain/analysisErrorCore.js";
import type { EvidenceBundle } from "../domain/evidenceBundle.js";

const bytePatternInputSchema = z
  .object(bytePatternFields)
  .superRefine(validateBytePattern);

/** Register native load-image, memory, and annotation CLI commands. */
export const registerCoreNativeCommands = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  registerAnnotationCommand(cli, logger, runDirectAnalysis);
  registerSearchNativeMemoryCommand(cli, logger, runDirectAnalysis);
  registerDispatchImplementationCommand(cli, logger, runDirectAnalysis);
  registerApplyDemangledNamesCommand(cli, logger, runDirectAnalysis);
  registerApplyObjcSignaturesCommand(cli, logger, runDirectAnalysis);
  registerApplyObjcIvarsCommand(cli, logger, runDirectAnalysis);
  registerInspectObjcSelectorRefsCommand(cli, logger, runDirectAnalysis);
  registerTraceNativeValuesInRegionCommand(cli, logger, runDirectAnalysis);
  registerResolveFunctionCallsCommand(cli, logger, runDirectAnalysis);
  registerInspectNativeRegionsCommand(cli, logger, runDirectAnalysis);
  registerEvaluateNativePcodeCommand(cli, logger, runDirectAnalysis);
  cli.command(CLI_COMMANDS.searchBytes, {
    description: "Find masked byte patterns in initialized provider memory",
    args: z.object({
      path: localPathStringSchema.describe("Local executable path"),
      pattern: bytePatternFields.pattern,
    }),
    options: z.object({
      mask: bytePatternFields.mask,
      start: z.string().optional().describe("Inclusive start address"),
      end: z.string().optional().describe("Inclusive end address"),
      cursor: z
        .string()
        .optional()
        .describe("Continuation from the same query's next_cursor"),
      limit: z
        .number()
        .int()
        .min(1)
        .max(MAX_BYTE_SEARCH_MATCHES)
        .default(100)
        .describe("Maximum matches on this page"),
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.searchBytes, async () => {
        const selection = {
          pattern: args.pattern,
          ...(options.mask === undefined ? {} : { mask: options.mask }),
        };
        const parsed = bytePatternInputSchema.safeParse(selection);
        if (!parsed.success)
          return projectAnalysisError(
            analysisInputErrorFromIssues(
              "search_bytes",
              parsed.error.issues,
              selection,
              { cause: parsed.error },
            ),
          );
        return runDirectAnalysis(
          args.path,
          "search_bytes",
          {
            pattern: parsed.data.pattern,
            ...(parsed.data.mask === undefined
              ? {}
              : { mask: parsed.data.mask }),
            limit: options.limit,
            ...(options.start === undefined ? {} : { start: options.start }),
            ...(options.end === undefined ? {} : { end: options.end }),
            ...(options.cursor === undefined ? {} : { cursor: options.cursor }),
          },
          directAnalysisOptionsFromCli(logger, options),
        ).then(projectCliAnalysisResult);
      }),
  });
  cli.command(CLI_COMMANDS.inspectNativeLoadImage, {
    description:
      "Inspect native load observations and supported snapshot verification",
    args: z.object({
      path: localPathStringSchema.describe("Local executable path"),
    }),
    options: z.object({
      ...analysisEvidenceDeliveryOptions,
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, CLI_COMMANDS.inspectNativeLoadImage, async () => {
          const delivery = {
            providerId: "auto",
            operation: "inspect_native_load_image",
            signal,
            detail: options.detail,
            evidenceOutput: options.evidence_output,
          };
          const invalid = cliEvidenceDeliveryInputError(delivery);
          if (invalid !== undefined) return projectAnalysisError(invalid);
          const complete = await runDirectAnalysis(
            args.path,
            "inspect_native_load_image",
            {},
            { ...directAnalysisOptionsFromCli(logger, options), signal },
          );
          return publishCliAnalysisEvidence(complete, delivery);
        }),
      ),
  });
  cli.command(CLI_COMMANDS.readBytes, {
    description:
      "Read provider memory bytes; Ghidra memory may include loader fixups and differ from file bytes",
    args: z.object({
      path: localPathStringSchema.describe("Local executable path"),
      address: z.string().describe("Exact provider memory address"),
    }),
    options: z.object({
      length: z
        .number()
        .int()
        .min(1)
        .default(256)
        .describe("Requested byte count"),
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.readBytes, () =>
        runDirectAnalysis(
          args.path,
          "read_bytes",
          { address: args.address, length: options.length },
          directAnalysisOptionsFromCli(logger, options),
        ).then(projectCliAnalysisResult),
      ),
  });
  cli.command(CLI_COMMANDS.addressToFileOffset, {
    description:
      "Map one analysis address to a file offset; memory bytes may differ and ranges may not be contiguous",
    args: z.object({
      path: localPathStringSchema.describe("Local executable path"),
      address: z.string().describe("Exact provider memory address"),
    }),
    options: z.object({
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.addressToFileOffset, () =>
        runDirectAnalysis(
          args.path,
          "address_to_file_offset",
          { address: args.address },
          directAnalysisOptionsFromCli(logger, options),
        ).then(projectCliAnalysisResult),
      ),
  });
  cli.command(CLI_COMMANDS.traceNativeValues, {
    description: "Trace bounded native def-use and call dependencies",
    args: z.object({
      path: localPathStringSchema.describe(
        "Local native executable or app path",
      ),
      procedure: nativeValueTraceInputSchema.shape.procedure.describe(
        "Explicit native procedure symbol or address",
      ),
    }),
    options: z.object({
      maxDepth: z
        .number()
        .int()
        .min(0)
        .max(16)
        .default(3)
        .describe("Maximum call traversal depth"),
      maxFunctions: z
        .number()
        .int()
        .min(1)
        .max(64)
        .default(16)
        .describe("Maximum function decompilations"),
      maxCallSites: z
        .number()
        .int()
        .min(1)
        .max(4096)
        .default(256)
        .describe("Maximum static call-site resolutions"),
      maxNodes: z
        .number()
        .int()
        .min(1)
        .max(20000)
        .default(5000)
        .describe("Maximum retained graph nodes"),
      maxEdges: z
        .number()
        .int()
        .min(1)
        .max(40000)
        .default(10000)
        .describe("Maximum retained graph edges"),
      address: z
        .string()
        .min(1)
        .optional()
        .describe("Interior address; trace stays inside the procedure"),
      direction: z
        .enum(["forward", "backward"])
        .default("forward")
        .describe("Walk uses or definitions from an interior address"),
      offset: z
        .number()
        .int()
        .min(0)
        .default(0)
        .describe("First graph node index"),
      limit: z
        .number()
        .int()
        .min(1)
        .max(5000)
        .default(1000)
        .describe("Maximum nodes on this page"),
      ...analysisEvidenceDeliveryOptions,
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, CLI_COMMANDS.traceNativeValues, async () => {
          const delivery = {
            providerId: "auto",
            operation: "trace_native_values",
            signal,
            detail: options.detail,
            evidenceOutput: options.evidence_output,
          };
          const invalid = cliEvidenceDeliveryInputError(delivery);
          if (invalid !== undefined) return projectAnalysisError(invalid);
          let sessionBundle: EvidenceBundle | undefined;
          const complete = await runDirectAnalysis(
            args.path,
            "trace_native_values",
            {
              procedure: args.procedure,
              max_depth: options.maxDepth,
              max_functions: options.maxFunctions,
              max_call_sites: options.maxCallSites,
              max_nodes: options.maxNodes,
              max_edges: options.maxEdges,
              offset: options.offset,
              limit: options.limit,
            },
            {
              ...directAnalysisOptionsFromCli(logger, options),
              signal,
              ...(options.evidence_output === undefined
                ? {}
                : {
                    onEvidenceBundle: (bundle: EvidenceBundle) => {
                      sessionBundle = bundle;
                    },
                  }),
            },
          );
          if (!complete.ok || options.evidence_output === undefined)
            return publishCliAnalysisEvidence(complete, delivery);
          if (sessionBundle === undefined)
            return projectAnalysisError(
              new AnalysisOutputError(
                "trace_native_values",
                "The CLI session did not return its retained Evidence bundle.",
              ).retainPartialObservation(complete.value),
            );
          const sources = cliEvidenceSourceClosure(
            complete.value,
            sessionBundle.records,
          );
          if (!sources.ok)
            return projectAnalysisError(
              sources.error.retainPartialObservation(complete.value),
            );
          return publishCliAnalysisEvidence(complete, {
            ...delivery,
            sourceEvidence: sources.value,
          });
        }),
      ),
  });
  cli.command(CLI_COMMANDS.inspectNativeDataType, {
    description: "Inspect one recovered database type or typed data object",
    args: z.object({
      path: z.string().describe("Local native executable or app path"),
    }),
    options: z.object({
      type: z.string().optional().describe("Exact database type category path"),
      address: z.string().optional().describe("Exact native address"),
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.inspectNativeDataType, () =>
        runDirectAnalysis(
          args.path,
          "inspect_native_data_type",
          {
            ...(options.type === undefined ? {} : { type: options.type }),
            ...(options.address === undefined
              ? {}
              : { address: options.address }),
          },
          directAnalysisOptionsFromCli(logger, options),
        ).then(projectCliAnalysisResult),
      ),
  });
  for (const [command, operation] of [
    [CLI_COMMANDS.inspectNativeInstruction, "inspect_native_instruction"],
    [CLI_COMMANDS.resolveNativeCallTargets, "resolve_native_call_targets"],
  ] as const) {
    cli.command(command, {
      description:
        operation === "inspect_native_instruction"
          ? "Inspect one native instruction with decoded operand facts"
          : "Resolve one static native call site",
      args: z.object({
        path: localPathStringSchema.describe(
          "Local native executable or app path",
        ),
        address: z.string().describe("Exact native address"),
      }),
      options: z.object({
        ...nativeOpenOptionFields,
      }),
      run: ({ args, options }) =>
        logCliCommand(logger, command, () =>
          runDirectAnalysis(
            args.path,
            operation,
            { address: args.address },
            directAnalysisOptionsFromCli(logger, options),
          ).then(projectCliAnalysisResult),
        ),
    });
  }
  registerNativeApiCommand(cli, logger, runDirectAnalysis);
  registerNativeUiActionCommand(cli, logger, runDirectAnalysis);
  registerNativeDispatchMetadataCommand(cli, logger, runDirectAnalysis);
};

const registerSearchNativeMemoryCommand = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.searchNativeMemory, {
    description: "Search program memory for bytes, immediates, or instructions",
    args: z.object({
      path: z.string().describe("Local executable path"),
      pattern: z.string().min(1).describe("Byte hex, immediate, or mnemonic"),
    }),
    options: z.object({
      kind: z
        .enum(["bytes", "immediate", "instruction"])
        .default("bytes")
        .describe("Search kind"),
      mask: z.string().min(1).optional().describe("Optional hex mask"),
      maxHits: z
        .number()
        .int()
        .min(1)
        .max(10_000)
        .default(256)
        .describe("Maximum hits to return"),
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.searchNativeMemory, () =>
        runDirectAnalysis(
          args.path,
          "search_native_memory",
          {
            kind: options.kind,
            pattern: args.pattern,
            ...(options.mask === undefined ? {} : { mask: options.mask }),
            max_hits: options.maxHits,
          },
          directAnalysisOptionsFromCli(logger, options),
        ),
      ),
  });
};

const registerDispatchImplementationCommand = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.inspectNativeDispatchImplementations, {
    description:
      "Map Objective-C class/selector implementations to containing procedures",
    args: z.object({
      path: z.string().describe("Target path used to bind the result evidence"),
    }),
    options: z.object({
      maxRecords: z
        .number()
        .int()
        .min(1)
        .max(20_000)
        .default(5_000)
        .describe("Maximum decoded implementation rows"),
      className: z.string().min(1).optional().describe("Exact class name"),
      selector: z.string().min(1).optional().describe("Exact selector"),
      resolveProcedures: z
        .boolean()
        .default(true)
        .describe("Resolve containing procedures"),
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      logCliCommand(
        logger,
        CLI_COMMANDS.inspectNativeDispatchImplementations,
        () =>
          runDirectAnalysis(
            args.path,
            "inspect_native_dispatch_implementations",
            {
              max_records: options.maxRecords,
              resolve_procedures: options.resolveProcedures,
              ...(options.className === undefined
                ? {}
                : { class_name: options.className }),
              ...(options.selector === undefined
                ? {}
                : { selector: options.selector }),
            },
            directAnalysisOptionsFromCli(logger, options),
          ),
      ),
  });
};

const registerApplyObjcSignaturesCommand = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.applyObjcSignatures, {
    description: "Plan or apply Objective-C method encodings as signatures",
    args: z.object({
      path: z.string().describe("Local executable path"),
    }),
    options: z.object({
      apply: z
        .boolean()
        .default(false)
        .describe("Apply eligible signatures; default is dry-run"),
      className: z.string().min(1).optional().describe("Exact class name"),
      selector: z.string().min(1).optional().describe("Exact selector"),
      maxMethods: z
        .number()
        .int()
        .min(1)
        .max(20_000)
        .default(500)
        .describe("Maximum methods to examine"),
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.applyObjcSignatures, () =>
        runDirectAnalysis(
          args.path,
          "apply_objc_signatures",
          {
            apply: options.apply,
            max_methods: options.maxMethods,
            ...(options.className === undefined
              ? {}
              : { class_name: options.className }),
            ...(options.selector === undefined
              ? {}
              : { selector: options.selector }),
          },
          directAnalysisOptionsFromCli(logger, options),
        ),
      ),
  });
};

const registerApplyObjcIvarsCommand = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.applyObjcIvars, {
    description: "Plan or apply Objective-C ivar layouts as Ghidra structures",
    args: z.object({
      path: z.string().describe("Local executable path"),
    }),
    options: z.object({
      apply: z
        .boolean()
        .default(false)
        .describe("Apply eligible structures; default is dry-run"),
      className: z.string().min(1).optional().describe("Exact class name"),
      maxClasses: z
        .number()
        .int()
        .min(1)
        .max(2_000)
        .default(200)
        .describe("Maximum classes to examine"),
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.applyObjcIvars, () =>
        runDirectAnalysis(
          args.path,
          "apply_objc_ivars",
          {
            apply: options.apply,
            max_classes: options.maxClasses,
            ...(options.className === undefined
              ? {}
              : { class_name: options.className }),
          },
          directAnalysisOptionsFromCli(logger, options),
        ),
      ),
  });
};

const registerInspectObjcSelectorRefsCommand = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.inspectObjcSelectorRefs, {
    description: "List static reference sites for Objective-C selectors",
    args: z.object({
      path: z.string().describe("Local executable path"),
    }),
    options: z.object({
      className: z.string().min(1).optional().describe("Exact class name"),
      selector: z.string().min(1).optional().describe("Exact selector"),
      maxRefs: z
        .number()
        .int()
        .min(1)
        .max(20_000)
        .default(2_000)
        .describe("Maximum reference sites"),
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.inspectObjcSelectorRefs, () =>
        runDirectAnalysis(
          args.path,
          "inspect_objc_selector_refs",
          {
            max_refs: options.maxRefs,
            ...(options.className === undefined
              ? {}
              : { class_name: options.className }),
            ...(options.selector === undefined
              ? {}
              : { selector: options.selector }),
          },
          directAnalysisOptionsFromCli(logger, options),
        ),
      ),
  });
};

const registerTraceNativeValuesInRegionCommand = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.traceNativeValuesInRegion, {
    description: "Trace static value flow inside one decompiler region",
    args: z.object({
      path: z.string().describe("Local executable path"),
      procedure: z.string().describe("Procedure symbol or address"),
      regionStart: z.string().describe("Region start address"),
    }),
    options: z.object({
      regionStop: z.string().min(1).optional().describe("Region stop address"),
      direction: z
        .enum(["forward", "backward"])
        .default("forward")
        .describe("Walk uses or definitions from the region start"),
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.traceNativeValuesInRegion, () =>
        runDirectAnalysis(
          args.path,
          "trace_native_values_in_region",
          {
            procedure: args.procedure,
            region_start: args.regionStart,
            direction: options.direction,
            ...(options.regionStop === undefined
              ? {}
              : { region_stop: options.regionStop }),
          },
          directAnalysisOptionsFromCli(logger, options),
        ),
      ),
  });
};

const registerResolveFunctionCallsCommand = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.resolveFunctionCalls, {
    description: "Resolve every call site in one procedure",
    args: z.object({
      path: z.string().describe("Local executable path"),
      procedure: z.string().describe("Procedure symbol or address"),
    }),
    options: z.object({
      maxSites: z
        .number()
        .int()
        .min(1)
        .max(4096)
        .default(256)
        .describe("Maximum call sites"),
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.resolveFunctionCalls, () =>
        runDirectAnalysis(
          args.path,
          "resolve_function_calls",
          { procedure: args.procedure, max_sites: options.maxSites },
          directAnalysisOptionsFromCli(logger, options),
        ),
      ),
  });
};

const registerInspectNativeRegionsCommand = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.inspectNativeRegions, {
    description: "List decompiler if, loop, and switch regions",
    args: z.object({
      path: z.string().describe("Local executable path"),
      procedure: z.string().describe("Procedure symbol or address"),
    }),
    options: z.object({ ...nativeOpenOptionFields }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.inspectNativeRegions, () =>
        runDirectAnalysis(
          args.path,
          "inspect_native_regions",
          { procedure: args.procedure },
          directAnalysisOptionsFromCli(logger, options),
        ),
      ),
  });
};

const registerEvaluateNativePcodeCommand = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.evaluateNativePcode, {
    description: "Evaluate bounded p-code inside one procedure",
    args: z.object({
      path: z.string().describe("Local executable path"),
      procedure: z.string().describe("Procedure symbol or address"),
    }),
    options: z.object({
      address: z.string().min(1).optional().describe("Start address"),
      maxSteps: z
        .number()
        .int()
        .min(1)
        .max(10_000)
        .default(256)
        .describe("Maximum p-code steps"),
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.evaluateNativePcode, () =>
        runDirectAnalysis(
          args.path,
          "evaluate_native_pcode",
          {
            procedure: args.procedure,
            max_steps: options.maxSteps,
            ...(options.address === undefined
              ? {}
              : { address: options.address }),
          },
          directAnalysisOptionsFromCli(logger, options),
        ),
      ),
  });
};

const registerApplyDemangledNamesCommand = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.applyDemangledNames, {
    description: "Plan or apply Swift-demangle names onto the symbol inventory",
    args: z.object({
      path: z.string().describe("Local executable path"),
    }),
    options: z.object({
      apply: z
        .boolean()
        .default(false)
        .describe("Apply the rename plan; default is dry-run"),
      pattern: z
        .string()
        .min(1)
        .optional()
        .describe("Literal filter on current or demangled names"),
      maxNames: z
        .number()
        .int()
        .min(1)
        .max(10_000)
        .default(500)
        .describe("Maximum mangled names to examine"),
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.applyDemangledNames, () =>
        runDirectAnalysis(
          args.path,
          "apply_demangled_names",
          {
            apply: options.apply,
            max_names: options.maxNames,
            ...(options.pattern === undefined
              ? {}
              : { pattern: options.pattern }),
          },
          directAnalysisOptionsFromCli(logger, options),
        ),
      ),
  });
};

const registerNativeDispatchMetadataCommand = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.inspectNativeDispatchMetadata, {
    description: "Inspect typed Objective-C and Swift dispatch metadata",
    args: z.object({
      path: localPathStringSchema.describe(
        "Target path used to bind the result evidence",
      ),
    }),
    options: z.object({
      maxRecords: nativeDispatchMetadataInputSchema.shape.max_records.describe(
        "Maximum symbol records to inspect",
      ),
      maxInputBytes: nativeDispatchMetadataInputSchema.shape.max_input_bytes,
      snapshot: snapshotSelectionOption.describe(
        "Load or update the local analysis snapshot",
      ),
      ...nativeOpenOptionFields,
    }),
    run: async ({ args, options }) =>
      logCliCommand(logger, "inspect-native-dispatch-metadata", () =>
        runDirectAnalysis(
          args.path,
          "inspect_native_dispatch_metadata",
          {
            max_records: options.maxRecords,
            ...(options.maxInputBytes === undefined
              ? {}
              : { max_input_bytes: options.maxInputBytes }),
          },
          directAnalysisOptionsFromCli(logger, options),
        ).then(projectCliAnalysisResult),
      ),
  });
};

const registerNativeUiActionCommand = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.traceNativeUiAction, {
    description:
      "Trace a compiled UI action selector to its native handler and direct callees",
    args: z.object({
      path: localPathStringSchema.describe(
        "Target path used to bind the result evidence",
      ),
      action: z
        .string()
        .min(1)
        .describe(
          "A unique compiled UI action selector or interface object ID",
        ),
    }),
    options: z.object({
      maxDepth: z
        .number()
        .int()
        .min(0)
        .max(32)
        .default(8)
        .describe("Maximum relationship depth"),
      maxNodes: z
        .number()
        .int()
        .min(1)
        .max(2_000)
        .default(250)
        .describe("Maximum returned graph nodes"),
      maxEdges: z
        .number()
        .int()
        .min(1)
        .max(5_000)
        .default(500)
        .describe("Maximum returned graph edges"),
      ...nativeOpenOptionFields,
    }),
    run: async ({ args, options }) =>
      logCliCommand(logger, "trace-native-ui-action", () =>
        runDirectAnalysis(
          args.path,
          "trace_native_ui_action",
          {
            action: args.action,
            max_depth: options.maxDepth,
            max_nodes: options.maxNodes,
            max_edges: options.maxEdges,
          },
          directAnalysisOptionsFromCli(logger, options),
        ).then(projectCliAnalysisResult),
      ),
  });
};

const registerNativeApiCommand = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.inspectNativeApi, {
    description: `Reconstruct one native function API boundary with evidence. ${addressOrProcedureGuidance} ${equalSelectorGuidance}`,
    args: z.object({
      path: localPathStringSchema.describe("App or program path"),
      address: z
        .string()
        .optional()
        .describe(`Procedure name or address. ${addressOrProcedureGuidance}`),
    }),
    options: z.object({
      procedure: z
        .string()
        .optional()
        .describe(
          `Procedure selector; use this option for symbols beginning with a dash. ${addressOrProcedureGuidance}`,
        ),
      snapshot: snapshotSelectionOption,
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, "inspect-native-api", () =>
        runDirectAnalysis(
          args.path,
          "inspect_native_api",
          {
            procedure: resolveCliAnalysisSelector(
              args.address,
              options.procedure,
              "procedure",
              "inspect_native_api",
            ),
          },
          directAnalysisOptionsFromCli(logger, options),
        ).then(projectCliAnalysisResult),
      ),
  });
};

const registerAnnotationCommand = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.annotateNativeFunction, {
    description: "Edit function annotations and return refreshed analysis",
    args: z.object({
      path: localPathStringSchema.describe("Local executable path"),
      procedure: z
        .string()
        .describe("Exact function entry address or unique name"),
    }),
    options: z.object({
      name: z.string().min(1).optional().describe("Analyst function name"),
      comment: z
        .string()
        .optional()
        .describe("Regular entry comment; empty text clears it"),
      "inline-comment": z
        .string()
        .optional()
        .describe("Inline entry comment; empty text clears it"),
      signature: z
        .string()
        .min(1)
        .optional()
        .describe("Ghidra C-like function signature"),
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.annotateNativeFunction, () =>
        runDirectAnalysis(
          args.path,
          "annotate_native_function",
          {
            procedure: args.procedure,
            ...(options.name === undefined ? {} : { name: options.name }),
            ...(options.comment === undefined
              ? {}
              : { comment: options.comment }),
            ...(options["inline-comment"] === undefined
              ? {}
              : { inline_comment: options["inline-comment"] }),
            ...(options.signature === undefined
              ? {}
              : { signature: options.signature }),
          },
          directAnalysisOptionsFromCli(logger, options),
        ).then(projectCliAnalysisResult),
      ),
  });
};
