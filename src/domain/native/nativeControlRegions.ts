import { z } from "zod";

/** Decompiler block-type names from Ghidra PcodeBlock.typeToName. */
const IF_BLOCKS = new Set(["properif", "ifelse", "ifgoto", "condition"]);
const LOOP_BLOCKS = new Set(["whiledo", "dowhile", "infloop"]);

/**
 * Map one Ghidra structured-block type name to a region kind.
 * Unrecognized parents stay unstructured.
 */
export const regionKindForDecompilerBlock = (
  blockType: string,
): "if" | "loop" | "switch" | "unstructured" => {
  const name = blockType.toLowerCase();
  if (IF_BLOCKS.has(name)) return "if";
  if (LOOP_BLOCKS.has(name)) return "loop";
  if (name === "switch") return "switch";
  return "unstructured";
};

const regionChildSchema = z.strictObject({
  start: z.string().nullable(),
  stop: z.string().nullable(),
});

/** One structured or unstructured decompiler region. */
export const nativeControlRegionSchema = z.strictObject({
  kind: z.enum(["if", "loop", "switch", "unstructured"]),
  start: z.string().nullable(),
  stop: z.string().nullable(),
  condition: z.string().nullable(),
  true_exit: z.string().nullable(),
  false_exit: z.string().nullable(),
  children: z.array(regionChildSchema),
  reason: z.string().nullable(),
});

/** Structured decompiler regions for one procedure. */
export const nativeControlRegionsSchema = z.strictObject({
  procedure: z.string().min(1),
  regions: z.array(nativeControlRegionSchema),
  limitations: z.array(z.string()),
});

export type NativeControlRegions = z.infer<typeof nativeControlRegionsSchema>;
