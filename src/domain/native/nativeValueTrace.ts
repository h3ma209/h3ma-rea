import { z } from "zod";
import { nativePcodeOperationSchema } from "./nativeValueFlow.js";

/** Work and output budgets for a static procedure-seeded dependency graph. */
export const nativeValueTraceInputSchema = z.strictObject({
  procedure: z.string().min(1),
  address: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Interior p-code address. When set, the trace stays inside the seed procedure.",
    ),
  direction: z.enum(["forward", "backward"]).default("forward"),
  max_depth: z.number().int().min(0).max(16).default(3),
  max_functions: z.number().int().min(1).max(64).default(16),
  max_call_sites: z.number().int().min(1).max(4096).default(256),
  max_nodes: z.number().int().min(1).max(20_000).default(5_000),
  max_edges: z.number().int().min(1).max(40_000).default(10_000),
  offset: z.number().int().min(0).default(0),
  limit: z.number().int().min(1).max(5_000).default(1_000),
});
/** Def-use observations and call relationships retain separate authority. */
export const nativeValueTraceSchema = z.strictObject({
  seed: z.string(),
  target_sha256: z.string(),
  nodes: z.array(
    z.strictObject({
      id: z.string(),
      procedure: z.string(),
      evidence_id: z.string(),
      kind: z.enum(["operation", "parameter"]),
      operation: nativePcodeOperationSchema.nullable(),
      parameter: z
        .strictObject({
          ordinal: z.number().int().nonnegative(),
          name: z.string(),
          data_type: z.string(),
        })
        .nullable(),
    }),
  ),
  edges: z.array(
    z.strictObject({
      source: z.string(),
      target: z.string(),
      input_index: z.number().int().nonnegative().nullable(),
      kind: z.enum([
        "def-use",
        "call",
        "parameter-use",
        "argument-binding",
        "return-binding",
      ]),
      status: z.enum(["derived", "direct", "resolved-indirect", "candidate"]),
      evidence_id: z.string(),
    }),
  ),
  procedures: z.array(
    z.strictObject({
      address: z.string(),
      depth: z.number().int().nonnegative(),
      evidence_id: z.string(),
      provider: z.string(),
      analysis_profile_digest: z.string().nullable(),
    }),
  ),
  unknowns: z.array(
    z.strictObject({
      procedure: z.string(),
      address: z.string().nullable(),
      reason: z.string(),
    }),
  ),
  total_nodes: z.number().int().nonnegative(),
  total_edges: z.number().int().nonnegative(),
  decompilations: z.number().int().nonnegative(),
  next_offset: z.number().int().nonnegative().nullable(),
  truncated: z.boolean(),
  limitations: z.array(z.string()),
});

export const normalizeTraceAddress = (value: string): string =>
  value.trim().toLowerCase().replace(/^0x/u, "");

/** Keep the forward uses or backward definitions of one interior address. */
export const compareTraceAddresses = (left: string, right: string): number => {
  const normalize = (value: string) =>
    BigInt(`0x${normalizeTraceAddress(value)}`);
  const a = normalize(left);
  const b = normalize(right);
  return a < b ? -1 : a > b ? 1 : 0;
};

const operationInRange = (
  address: string,
  start: string,
  stop: string,
): boolean =>
  compareTraceAddresses(start, address) <= 0 &&
  compareTraceAddresses(address, stop) <= 0;

/** Keep nodes whose p-code address lies in the closed range and their parameter edges. */
export const filterNativeValueGraphByRange = <
  Node extends {
    readonly id: string;
    readonly operation: { readonly address: string } | null;
    readonly kind: "operation" | "parameter";
  },
  Edge extends { readonly source: string; readonly target: string },
>(
  nodes: readonly Node[],
  edges: readonly Edge[],
  start: string,
  stop: string,
): { readonly nodes: Node[]; readonly edges: Edge[] } => {
  const keep = new Set<string>();
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const inRangeNode = (node: Node): boolean =>
    node.kind === "parameter" ||
    (node.operation !== null &&
      operationInRange(node.operation.address, start, stop));
  for (const node of nodes) {
    if (
      node.kind === "operation" &&
      node.operation !== null &&
      operationInRange(node.operation.address, start, stop)
    )
      keep.add(node.id);
  }
  let grew = true;
  while (grew) {
    grew = false;
    for (const edge of edges) {
      const source = nodeById.get(edge.source);
      const target = nodeById.get(edge.target);
      if (source === undefined || target === undefined) continue;
      if (keep.has(edge.source) && inRangeNode(target) && !keep.has(edge.target)) {
        keep.add(edge.target);
        grew = true;
      }
      if (keep.has(edge.target) && inRangeNode(source) && !keep.has(edge.source)) {
        keep.add(edge.source);
        grew = true;
      }
    }
  }
  return {
    nodes: nodes.filter((node) => keep.has(node.id)),
    edges: edges.filter(
      (edge) => keep.has(edge.source) && keep.has(edge.target),
    ),
  };
};

export const sliceNativeValueGraph = <
  Node extends { readonly id: string; readonly operation: { readonly address: string } | null },
  Edge extends { readonly source: string; readonly target: string },
>(
  nodes: readonly Node[],
  edges: readonly Edge[],
  address: string,
  direction: "forward" | "backward",
): { readonly nodes: Node[]; readonly edges: Edge[]; readonly matched: boolean } => {
  const wanted = normalizeTraceAddress(address);
  const seeds = nodes.filter(
    (node) =>
      node.operation !== null &&
      normalizeTraceAddress(node.operation.address) === wanted,
  );
  if (seeds.length === 0) return { nodes: [], edges: [], matched: false };
  const keep = new Set(seeds.map((node) => node.id));
  let grew = true;
  while (grew) {
    grew = false;
    for (const edge of edges) {
      const from = direction === "forward" ? edge.source : edge.target;
      const to = direction === "forward" ? edge.target : edge.source;
      if (keep.has(from) && !keep.has(to)) {
        keep.add(to);
        grew = true;
      }
    }
  }
  return {
    nodes: nodes.filter((node) => keep.has(node.id)),
    edges: edges.filter(
      (edge) => keep.has(edge.source) && keep.has(edge.target),
    ),
    matched: true,
  };
};
