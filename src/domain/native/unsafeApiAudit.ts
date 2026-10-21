import { z } from "zod";

export const unsafeApiFindingSchema = z.strictObject({
  api: z.string(),
  reference_address: z.string(),
  caller_procedure: z.string().nullable(),
  severity: z.enum(["critical", "high", "medium"]),
  remediation: z.string(),
});

export const auditUnsafeApisResultSchema = z.strictObject({
  findings: z.array(unsafeApiFindingSchema),
  total_unsafe_calls: z.number().int().min(0),
  limitations: z.array(z.string()),
});

export type AuditUnsafeApisResult = z.infer<typeof auditUnsafeApisResultSchema>;
