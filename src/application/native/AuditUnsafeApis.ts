import { z } from "zod";

import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import {
  auditUnsafeApisResultSchema,
  type AuditUnsafeApisResult,
} from "../../domain/native/unsafeApiAudit.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import { err, ok } from "../../domain/result.js";
import type { AnalysisOperationPort } from "../AnalysisProvider.js";
import type { EnhancedResult } from "../EnhancedToolTypes.js";

const BANNED_APIS: Readonly<
  Record<
    string,
    { severity: "critical" | "high" | "medium"; remediation: string }
  >
> = {
  gets: { severity: "critical", remediation: "Use fgets or getline instead" },
  strcpy: { severity: "high", remediation: "Use strlcpy or strncpy_s instead" },
  strcat: { severity: "high", remediation: "Use strlcat or strncat_s instead" },
  sprintf: { severity: "high", remediation: "Use snprintf instead" },
  vsprintf: { severity: "high", remediation: "Use vsnprintf instead" },
  system: {
    severity: "critical",
    remediation: "Avoid shell invocation; use posix_spawn or execve",
  },
  popen: { severity: "high", remediation: "Use pipe and posix_spawn instead" },
};

const nameListSchema = z.array(
  z.object({
    address: z.string(),
    name: z.string(),
  }),
);

export const auditUnsafeApis = async (
  analysis: AnalysisOperationPort,
  input: Record<string, unknown>,
  signal?: AbortSignal,
): EnhancedResult => {
  const namesRes = await analysis.execute(
    "list_names",
    {},
    signal === undefined ? {} : { signal },
  );

  if (!namesRes.ok) return namesRes;

  const parsedNames = nameListSchema.safeParse(namesRes.value.result);
  if (!parsedNames.success)
    return err(
      new AnalysisOutputError(
        "audit_unsafe_apis",
        "Failed to parse binary names",
        {
          cause: parsedNames.error,
        },
      ),
    );

  const findings: AuditUnsafeApisResult["findings"] = [];

  for (const item of parsedNames.data) {
    if (signal?.aborted)
      return err(
        new AnalysisCancelledError("audit_unsafe_apis", {
          cause: signal.reason,
        }),
      );

    const cleanName = item.name.replace(/^_+/u, "");
    const banned = BANNED_APIS[cleanName];
    if (banned) {
      findings.push({
        api: item.name,
        reference_address: item.address,
        caller_procedure: null,
        severity: banned.severity,
        remediation: banned.remediation,
      });
    }
  }

  const result: AuditUnsafeApisResult = {
    findings,
    total_unsafe_calls: findings.length,
    limitations: [],
  };

  return ok(jsonValueSchema.parse(result));
};
