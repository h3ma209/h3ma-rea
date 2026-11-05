import { requireOutputSchema } from "./toolOutputSchemaPrimitives.js";
import { analysisDetailSchema } from "./analysisDetail.js";
import { z } from "zod";

import { enhancedInputSchemas } from "./enhancedInputs.js";
import { enhancedOutputSchemas } from "./toolOutputSchemaGroups.js";
import { examplesFor } from "./toolContractHelpers.js";
import type { ToolContract } from "./toolContractTypes.js";
import { toolContractMetadata } from "./toolEffects.js";
import { FUNCTION_WORKFLOW_TOOL_CONTRACTS } from "./functionWorkflowToolContracts.js";

const enhanced = <
  Name extends keyof typeof enhancedOutputSchemas,
  Schema extends z.ZodObject,
>(
  name: Name,
  description: string,
  inputSchema: Schema,
) =>
  ({
    name,
    ...toolContractMetadata(name),
    description,
    kind: "enhanced",
    requiresActiveTarget: true,
    inputSchema,
    outputSchema: requireOutputSchema(enhancedOutputSchemas, name),
    examples: examplesFor(name, inputSchema),
  }) satisfies ToolContract<Name, Schema>;

/** Workflow tools composed from one or more provider operations. */
export const ENHANCED_TOOL_CONTRACTS = [
  enhanced(
    "inspect_native_dispatch_metadata",
    "Inspect the bound provider's name inventory for Objective-C class/method symbols and Swift mangled symbols, returning at most max_records decoded names. Optional objc_class_import_addresses request exact pointer-slot binding facts for those addresses; they are decoded only from the selected Mach-O slice and retain partial or unsupported coverage when not established. Includes target SHA-256 when available, provider identity/version, analysis-profile digest, facet coverage, and per-record Evidence. This is static symbol and metadata evidence, not runtime metadata: ivar layouts, protocol conformances, witness/class tables, and relative pointers are explicitly marked unsupported unless a provider supplies those decoders. The provider controls how its name inventory is acquired. The Mach-O byte reader holds the whole file in memory: max_input_bytes (default 64 MiB, at most 1 GiB) bounds it, and results record input_admission.",
    enhancedInputSchemas.inspect_native_dispatch_metadata,
  ),
  enhanced(
    "inspect_native_dispatch_implementations",
    "Join decoded Objective-C class/selector/implementation rows with the bound provider's containing-procedure inventory. Optional class_name and selector filters are exact. Unmapped implementations and unresolved procedure joins remain explicit. Runtime dispatch is unknown.",
    enhancedInputSchemas.inspect_native_dispatch_implementations,
  ),
  enhanced(
    "apply_demangled_names",
    "Plan, and optionally apply, analyst names from Swift demangle results for mangled symbols in the bound name inventory. apply defaults to false and returns the rename plan only. Application uses set_addresses_names and reports per-address readback. Original executable bytes are unchanged.",
    enhancedInputSchemas.apply_demangled_names,
  ),
  enhanced(
    "apply_objc_signatures",
    "Plan, and optionally apply, Ghidra C signatures from decoded Objective-C method type encodings. apply defaults to false. Each applied signature uses annotate_native_function on that method's containing procedure.",
    enhancedInputSchemas.apply_objc_signatures,
  ),
  enhanced(
    "resolve_function_calls",
    "Resolve every call site in one procedure. Provider call references stay distinct from Objective-C and Swift metadata joins. Ambiguous and unresolved sites stay explicit.",
    enhancedInputSchemas.resolve_function_calls,
  ),
  enhanced(
    "apply_objc_ivars",
    "Plan, and optionally apply, Ghidra structures from decoded Objective-C ivar layouts. apply defaults to false.",
    enhancedInputSchemas.apply_objc_ivars,
  ),
  enhanced(
    "trace_native_values_in_region",
    "Trace a bounded static dependency graph inside one decompiler region of an explicit procedure.",
    enhancedInputSchemas.trace_native_values_in_region,
  ),
  enhanced(
    "get_objc_classes",
    "Discover Objective-C class labels, optionally filtering by literal substring. Rows are coalesced only when exact selected-image pointer-fixup evidence proves that their own addresses bind the same imported class symbol, binding stream, raw library ordinal and resolved library, weak status, and addend. Rows without that evidence remain separate, with identity coverage reported as unknown, partial, or unsupported.",
    enhancedInputSchemas.get_objc_classes,
  ),
  enhanced(
    "get_objc_protocols",
    "Discover and deduplicate Objective-C and Swift protocol labels.",
    enhancedInputSchemas.get_objc_protocols,
  ),
  enhanced(
    "batch_decompile",
    "Decompile each explicit procedure symbol or address, with one provider read active per batch. Preserves each input selector in address and reports the observed canonical entry and entry label in procedure; identity or label failures remain explicit without discarding usable pseudocode. Returns ordered per-item outcomes and aggregate counts. An unavailable item means the provider returned null pseudocode; its limitations retain any reported reason without asserting provider capability or retryability. Errors report failed operations or malformed output. Failed counts include unavailable items. The complete reply carries every pseudocode body. Select detail summary to retain the batch and receive only counts, then read rows or one body by index through inspect_analysis_view. A per-function limit is not a batch deadline; allow for every item or split calls.",
    enhancedInputSchemas.batch_decompile.extend({
      detail: analysisDetailSchema,
    }),
  ),
  enhanced(
    "decompile_all",
    "Write provider pseudocode for every analyzed function, or a filtered subset, into a caller-selected directory and return only a manifest. Each file records the provider function name, canonical address, inclusive body ranges when procedure_info supplies them, and that function's procedure_info and pseudocode limitations. Each function's index record keeps its complete limitations. Evidence keeps at most eight first-observed distinct per-function limitations within an encoded-text budget; the omitted count measures observations, not distinct warnings. The manifest reports counts, the output directory, the index path, at most 32 failure details within 2,048 JSON-encoded UTF-8 bytes (names can be omitted; full names remain in the index), provider identity, and the analysis-profile digest. Pseudocode stays in the files. An existing directory is refused unless resume is set and the journal matches the target SHA-256, provider, and analysis profile; verified files are skipped and conflicting files are left unchanged. layout dwarf reports that compilation-unit paths are unavailable and names files by address. A failure of one function does not stop the others. Functions procedure_info classifies as external are counted as external, get no file, and are not decompiled; a resume skips them. Cancellation leaves files already written. Per-function limits do not bound the whole call; use limit and resume to select work that fits the client deadline, including import, listing and file work.",
    enhancedInputSchemas.decompile_all,
  ),
  enhanced(
    "get_call_graph",
    "Resolve one symbol or address to its canonical procedure entry, then traverse the bound provider's caller or callee relationships until the reachable graph is exhausted. Every node uses a canonical address and has an ok/error status; failures use safe typed projections. Unresolved indirect calls may be missing and results are not a whole-program CFG. Select detail summary for a bounded first node page with shared message references; native-observation pages and native-context fields retain complete source access.",
    enhancedInputSchemas.get_call_graph.extend({
      detail: analysisDetailSchema,
    }),
  ),
  enhanced(
    "analyze_swift_types",
    'Categorize analyzed Swift procedure names using their manglings or same-address Swift symbol aliases. Decodes legacy and literal modern nominal contexts into classes, structs, enums, protocols, and extensions. Preserves provider names and supporting mangled_names; unresolved categories appear in other and in unclassified, which remains inline even under category filters. Returns deduplicated procedure-name counts, not unique source types, plus identification limitations. Optionally select one category and/or apply a case-sensitive literal filter to provider names or supporting manglings; for example, use {category: "structs", pattern: "Pair"}.',
    enhancedInputSchemas.analyze_swift_types,
  ),
  enhanced(
    "find_xrefs_to_name",
    "Resolve an exact name against the bound provider's name inventory and return a resolved or unresolved result. Unresolved names use the stable name_not_found reason; this xref workflow returns address-only projections.",
    enhancedInputSchemas.find_xrefs_to_name,
  ),
  enhanced(
    "binary_overview",
    "Return the bound document and procedure/string counts totalling every row of the bound provider's inventories (inventory_coverage: provider scope, discovery unknown; not comparable across providers), plus every segment and segment_count when the provider supports segment enumeration. If segment fields are omitted, segment coverage is unavailable rather than empty. When every observed segment agrees on an analysis image base, return it as image_base so callers can relate provider addresses to their loader coordinates. Use search_procedures, list_procedures, or analyze_function directly when you already know which procedure to inspect.",
    enhancedInputSchemas.binary_overview,
  ),
  ...FUNCTION_WORKFLOW_TOOL_CONTRACTS,
  enhanced(
    "trace_feature",
    "Trace the complete literal query, preserving spaces, through every matching string and procedure and their xrefs. Preserve an explicit unavailable owner for a non-retryable containment capability refusal. Returns observations and residual unknowns without inferring reference kinds; truncated only reports an observed reference cap. For a procedure match, use procedure_references with direction incoming for provider-reported kinds when supported; it covers the procedure body, so compare target addresses when selecting exact-entry references. Select detail summary to retain complete Evidence and page matches, references and unknowns with inspect_analysis_view kind native-feature-trace.",
    enhancedInputSchemas.trace_feature.extend({ detail: analysisDetailSchema }),
  ),
  enhanced(
    "trace_call_path",
    "Resolve start and optional goal symbols or addresses to canonical procedure entries, then trace direct callers or callees until the graph is exhausted or the goal is reached. Results use canonical addresses; Evidence preserves supplied selectors. Returns visited nodes, direct-call edges, a shortest traversal path, provider failures, and residual unknowns. A requested goal is unknown when unresolved expansions prevent proving it absent; unresolved indirect calls remain unknown.",
    enhancedInputSchemas.trace_call_path,
  ),
  enhanced(
    "trace_native_ui_action",
    "Trace one unique compiled UI action, object ID, native symbol or exact function address through authored connections, encoded or symbolized Objective-C handlers, and bounded static call references. Typed direct and resolved indirect calls, ambiguous candidates, inferred untyped provider callees, and targetless sites remain distinct. Runtime reachability is unknown; use trace_native_values for recovered value dependencies.",
    enhancedInputSchemas.trace_native_ui_action,
  ),
  enhanced(
    "inspect_binary_protections",
    "Inspect binary mitigation and hardening flags including PIE, Stack Canaries, ARC, and Hardened Runtime.",
    enhancedInputSchemas.inspect_binary_protections,
  ),
  enhanced(
    "detect_crypto_primitives",
    "Scan binary string tables and read-only data for cryptographic constants, cipher suite names, and hashing primitives.",
    enhancedInputSchemas.detect_crypto_primitives,
  ),
  enhanced(
    "audit_unsafe_apis",
    "Audit binary symbols for banned or high-risk C runtime functions (e.g. gets, strcpy, system) and provide safe remediations.",
    enhancedInputSchemas.audit_unsafe_apis,
  ),
  enhanced(
    "inspect_macho_bindings",
    "Inspect Mach-O dynamic symbol bindings, stub helpers, lazy symbol pointers, and external dylib references.",
    enhancedInputSchemas.inspect_macho_bindings,
  ),
  enhanced(
    "trace_native_function_calls",
    "Trace live invocations of a native function, capturing entry registers and caller context.",
    enhancedInputSchemas.trace_native_function_calls,
  ),
  enhanced(
    "resolve_external_symbols",
    "Auto-locate and link matching detached .dSYM debug symbol bundles on macOS using DWARF UUID and Spotlight metadata.",
    enhancedInputSchemas.resolve_external_symbols,
  ),
  enhanced(
    "scan_embedded_keys",
    "Scan mapped binary string tables, rodata, and text sections for API keys, bearer tokens, PEM certificates, and high Shannon entropy candidate secrets.",
    enhancedInputSchemas.scan_embedded_keys,
  ),
  enhanced(
    "inspect_objc_selector_refs",
    "List static reference sites for decoded Objective-C selectors, resolving containing procedures where possible.",
    enhancedInputSchemas.inspect_objc_selector_refs,
  ),
  enhanced(
    "inspect_swift_concurrency",
    "Analyze Swift async/await tasks, actor boundaries, and continuation points from mangled concurrency runtime symbols.",
    enhancedInputSchemas.inspect_swift_concurrency,
  ),
  enhanced(
    "diff_binary_revisions",
    "Compute high-level semantic differences between two binary revisions (symbols added/removed, altered strings, modified procedure footprints).",
    enhancedInputSchemas.diff_binary_revisions,
  ),
  enhanced(
    "trace_native_values",
    "Trace a bounded static dependency graph from one explicit native procedure. Includes high-p-code def-use, constants, operators, memory and branch operations, resolved call edges, and derived argument/parameter and return/output bindings. Missing bindings, alias semantics, persistent state and RNG roles remain unknown. Budgets bound depth, decompilations, graph size and payloads; nodes are paginated. A Ghidra per-function timeout does not bound the whole traversal; allow startup, every attempted function and other work, or reduce max_functions.",
    enhancedInputSchemas.trace_native_values,
  ),
] as const satisfies readonly ToolContract[];
