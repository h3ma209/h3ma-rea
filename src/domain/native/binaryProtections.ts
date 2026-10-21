import { z } from "zod";

export const binaryMitigationFlagsSchema = z.strictObject({
  format: z.enum(["macho", "elf", "pe", "unknown"]),
  pie: z.boolean(),
  stack_canary: z.boolean(),
  arc: z.boolean().nullable(),
  nx_dep: z.boolean(),
  relro: z.enum(["full", "partial", "none", "unknown"]),
  hardened_runtime: z.boolean().nullable(),
  encrypted: z.boolean().nullable(),
  limitations: z.array(z.string()),
});

export type BinaryMitigationFlags = z.infer<typeof binaryMitigationFlagsSchema>;
