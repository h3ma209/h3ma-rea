import { z } from "zod";

const hexToken = "(?:[0-9a-fA-F]{2}|\\?\\?)";

/** Hex bytes with optional spaces and `??` wildcards. */
export const nativeMemorySearchBytesPatternSchema = z
  .string()
  .min(2)
  .regex(
    new RegExp(`^\\s*${hexToken}(?:\\s*${hexToken})*\\s*$`, "u"),
    "Byte patterns use even hex digits or ?? wildcards, optionally spaced",
  );

/** One memory, immediate, or instruction hit with containing-procedure resolution. */
export const nativeMemorySearchHitSchema = z.strictObject({
  address: z.string().min(1),
  kind: z.enum(["bytes", "immediate", "instruction"]),
  bytes_hex: z.string().regex(/^(?:[a-f0-9]{2})*$/u).nullable(),
  mnemonic: z.string().nullable(),
  operands: z.string().nullable(),
  immediate: z.string().nullable(),
  procedure: z.discriminatedUnion("found", [
    z.strictObject({
      found: z.literal(true),
      address: z.string().min(1),
      name: z.string().min(1),
    }),
    z.strictObject({
      found: z.literal(false),
      address: z.null(),
      name: z.null(),
      reason: z.enum(["outside_segments", "not_in_procedure"]),
    }),
  ]),
});

/** Bounded memory search over one analyzed program. */
export const nativeMemorySearchSchema = z.strictObject({
  kind: z.enum(["bytes", "immediate", "instruction"]),
  pattern: z.string().min(1),
  hits: z.array(nativeMemorySearchHitSchema),
  hit_count: z.number().int().min(0),
  exhaustive: z.boolean(),
  limitations: z.array(z.string()),
});

export type NativeMemorySearch = z.infer<typeof nativeMemorySearchSchema>;
