import { z } from "zod";

/** Classification of discovered embedded secret or sensitive key pattern. */
export const secretPatternKindSchema = z.enum([
  "high_entropy_string",
  "pem_certificate_or_key",
  "jwt_token",
  "aws_access_key",
  "openai_api_key",
  "github_token",
  "generic_api_credential",
]);

export const embeddedSecretFindingSchema = z.strictObject({
  kind: secretPatternKindSchema,
  address: z.string().nullable(),
  value: z.string(),
  entropy: z.number().min(0).max(8),
  confidence: z.enum(["high", "medium", "low"]),
  description: z.string(),
});

export const scanEmbeddedKeysResultSchema = z.strictObject({
  findings: z.array(embeddedSecretFindingSchema),
  total_strings_scanned: z.number().int().min(0),
  high_entropy_count: z.number().int().min(0),
  limitations: z.array(z.string()),
});

export type ScanEmbeddedKeysResult = z.infer<
  typeof scanEmbeddedKeysResultSchema
>;

/** Calculate Shannon entropy of a string (bits per char, 0.0 - 8.0). */
export const calculateEntropy = (str: string): number => {
  if (str.length === 0) return 0;
  const frequencies = new Map<string, number>();
  for (const ch of str) {
    frequencies.set(ch, (frequencies.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of frequencies.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
};

const SECRET_PATTERNS: readonly {
  kind: z.infer<typeof secretPatternKindSchema>;
  regex: RegExp;
  confidence: "high" | "medium" | "low";
  description: string;
}[] = [
  {
    kind: "pem_certificate_or_key",
    regex: /-----BEGIN\s+(?:RSA\s+)?(?:PRIVATE\s+KEY|CERTIFICATE)-----/u,
    confidence: "high",
    description: "Embedded PEM certificate or private key header",
  },
  {
    kind: "aws_access_key",
    regex:
      /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/u,
    confidence: "high",
    description: "AWS Access Key identifier pattern",
  },
  {
    kind: "github_token",
    regex: /gh[pousr]_[A-Za-z0-9_]{36,255}/u,
    confidence: "high",
    description: "GitHub personal or OAuth token pattern",
  },
  {
    kind: "openai_api_key",
    regex: /sk-(?:proj-)?[A-Za-z0-9_-]{32,}/u,
    confidence: "high",
    description: "OpenAI API secret key pattern",
  },
  {
    kind: "jwt_token",
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/u,
    confidence: "high",
    description: "Signed JSON Web Token (JWT)",
  },
];

/** Analyze string for secrets or abnormal entropy. */
export const inspectStringForSecrets = (
  value: string,
  minEntropy = 4.5,
): {
  kind: z.infer<typeof secretPatternKindSchema>;
  entropy: number;
  confidence: "high" | "medium" | "low";
  description: string;
} | null => {
  const trimmed = value.trim();
  if (trimmed.length < 8) return null;

  for (const pattern of SECRET_PATTERNS) {
    if (pattern.regex.test(trimmed)) {
      return {
        kind: pattern.kind,
        entropy: calculateEntropy(trimmed),
        confidence: pattern.confidence,
        description: pattern.description,
      };
    }
  }

  const entropy = calculateEntropy(trimmed);
  if (entropy >= minEntropy && trimmed.length >= 20 && !trimmed.includes(" ")) {
    return {
      kind: "high_entropy_string",
      entropy,
      confidence: entropy > 5.2 ? "medium" : "low",
      description: `High Shannon entropy string (${entropy} bits/char)`,
    };
  }

  return null;
};
