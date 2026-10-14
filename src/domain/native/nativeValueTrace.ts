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

const normalizeTraceAddress = (value: string): string =>
  value.trim().toLowerCase().replace(/^0x/u, "");

/** Keep the forward uses or backward definitions of one interior address. */
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
