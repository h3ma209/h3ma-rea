import { z } from "zod";

export const cryptoPrimitiveFindingSchema = z.strictObject({
  algorithm: z.enum(["AES", "SHA256", "SHA1", "MD5", "ChaCha20", "RSA_ASN1"]),
  address: z.string(),
  description: z.string(),
  confidence: z.enum(["high", "medium"]),
});

export const detectCryptoPrimitivesResultSchema = z.strictObject({
  primitives: z.array(cryptoPrimitiveFindingSchema),
  total_constants_found: z.number().int().min(0),
  limitations: z.array(z.string()),
});

export type DetectCryptoPrimitivesResult = z.infer<
  typeof detectCryptoPrimitivesResultSchema
>;
