import { z } from "zod";

import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { nativeControlRegionsSchema } from "../../domain/native/nativeControlRegions.js";
import {
  filterNativeValueGraphByRange,
  nativeValueTraceSchema,
  normalizeTraceAddress,
  sliceNativeValueGraph,
} from "../../domain/native/nativeValueTrace.js";
import { nativeValueTraceInRegionInputSchema } from "../../domain/native/nativeValueTraceRegion.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import { err, ok } from "../../domain/result.js";
import type { AnalysisOperationPort } from "../AnalysisProvider.js";
import type { EnhancedResult } from "../EnhancedToolTypes.js";
import { traceNativeValues } from "./NativeValueTrace.js";

/** Trace static value flow inside one decompiler region address range. */
export const traceNativeValuesInRegion = async (
  analysis: AnalysisOperationPort,
  input: z.output<typeof nativeValueTraceInRegionInputSchema>,
  signal?: AbortSignal,
): EnhancedResult => {
  const regions = await analysis.execute(
    "inspect_native_regions",
    { procedure: input.procedure },
    signal === undefined ? {} : { signal },
  );
  if (!regions.ok) return regions;
  const parsedRegions = nativeControlRegionsSchema.safeParse(regions.value.result);
  if (!parsedRegions.success)
    return err(
      new AnalysisOutputError(
        "trace_native_values_in_region",
        "inspect_native_regions did not match the region contract",
        { cause: parsedRegions.error },
      ),
    );
  const wanted = normalizeTraceAddress(input.region_start);
  const matched = parsedRegions.data.regions.filter(
    (region) =>
      region.start !== null &&
      normalizeTraceAddress(region.start) === wanted &&
      (input.region_stop === undefined ||
        (region.stop !== null &&
          normalizeTraceAddress(region.stop) ===
            normalizeTraceAddress(input.region_stop))),
  );
  const region = matched[0];
  if (region === undefined || region.start === null || region.stop === null)
    return err(
      new AnalysisOutputError(
        "trace_native_values_in_region",
        "No decompiler region matched region_start and region_stop",
      ),
    );
  const traced = await traceNativeValues(
    analysis,
    {
      ...input,
      max_depth: 0,
      max_functions: 1,
      address: undefined,
    },
    signal,
  );
  if (!traced.ok) return traced;
  const graph = nativeValueTraceSchema.parse(traced.value);
  let nodes = graph.nodes;
  let edges = graph.edges;
  const ranged = filterNativeValueGraphByRange(
    nodes,
    edges,
    region.start,
    region.stop,
  );
  nodes = ranged.nodes;
  edges = ranged.edges;
  const sliced = sliceNativeValueGraph(
    nodes,
    edges,
    region.start,
    input.direction,
  );
  const regionLimitations = [
    "Value flow was limited to one decompiler region address range inside the seed procedure.",
  ];
  if (sliced.matched) {
    nodes = sliced.nodes;
    edges = sliced.edges;
    regionLimitations.push(
      `Region trace walked ${input.direction} from the region start.`,
    );
  } else if (nodes.length > 0)
    regionLimitations.push(
      "No p-code operation sits at the region start; the full in-range graph is returned.",
    );
  else
    return err(
      new AnalysisOutputError(
        "trace_native_values_in_region",
        "The region address range contains no recovered p-code operations",
      ),
    );
  const page = nodes.slice(input.offset, input.offset + input.limit);
  const pageIds = new Set(page.map(({ id }) => id));
  return ok(
    jsonValueSchema.parse({
      ...graph,
      seed: input.procedure,
      nodes: page,
      edges: edges.filter(({ source }) => pageIds.has(source)),
      total_nodes: nodes.length,
      total_edges: edges.length,
      next_offset:
        input.offset + page.length < nodes.length
          ? input.offset + page.length
          : null,
      truncated: graph.truncated || page.length !== nodes.length,
      region: {
        kind: region.kind,
        start: region.start,
        stop: region.stop,
      },
      limitations: [...graph.limitations, ...regionLimitations],
    }),
  );
};
