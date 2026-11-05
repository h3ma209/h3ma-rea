import { z } from "zod";

/** One concrete value recovered while evaluating lifted p-code. */
export const nativePcodeValueSchema = z.strictObject({
  address: z.string().min(1),
  register: z.string().nullable(),
  hex: z
    .string()
    .regex(/^(?:[0-9a-f]{2})*$/u)
    .nullable(),
});

/** Bounded static evaluation of one procedure's lifted p-code. */
export const nativePcodeEvaluationSchema = z.strictObject({
  procedure: z.string().min(1),
  start: z.string().min(1),
  steps: z.number().int().min(0),
  values: z.array(nativePcodeValueSchema),
  unknown: z.string().nullable(),
  limitations: z.array(z.string()),
});

export type NativePcodeEvaluation = z.infer<typeof nativePcodeEvaluationSchema>;
