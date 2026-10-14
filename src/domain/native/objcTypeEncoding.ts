const PRIMITIVE_TYPES: Readonly<Record<string, string>> = {
  c: "char",
  i: "int",
  s: "short",
  l: "long",
  q: "long long",
  C: "unsigned char",
  I: "unsigned int",
  S: "unsigned short",
  L: "unsigned long",
  Q: "unsigned long long",
  f: "float",
  d: "double",
  B: "unsigned char",
  v: "void",
  "*": "char *",
  "@": "void *",
  ":": "void *",
};

const QUALIFIERS = new Set(["r", "n", "N", "o", "O", "R", "V"]);

interface DecodedType {
  readonly cType: string;
  readonly next: number;
  readonly isVoid: boolean;
}

const readType = (source: string, index: number): DecodedType | null => {
  let cursor = index;
  while (cursor < source.length && QUALIFIERS.has(source[cursor] ?? ""))
    cursor += 1;
  if (cursor >= source.length) return null;
  const token = source[cursor];
  if (token === "^") {
    const inner = readType(source, cursor + 1);
    if (inner === null) return null;
    const cType = inner.cType.endsWith("*")
      ? `${inner.cType}*`
      : `${inner.cType} *`;
    return { cType, next: inner.next, isVoid: false };
  }
  if (token === undefined || PRIMITIVE_TYPES[token] === undefined) return null;
  let next = cursor + 1;
  if (token === "@" && source[next] === '"') {
    const end = source.indexOf('"', next + 1);
    if (end < 0) return null;
    next = end + 1;
  }
  return {
    cType: PRIMITIVE_TYPES[token],
    next,
    isVoid: token === "v",
  };
};

const skipDigits = (source: string, index: number): number => {
  let cursor = index;
  while (cursor < source.length && source[cursor]! >= "0" && source[cursor]! <= "9")
    cursor += 1;
  return cursor;
};

const cIdentifier = (selector: string): string | null => {
  const name = selector.replaceAll(":", "_");
  return /^[A-Za-z_][A-Za-z0-9_]*$/u.test(name) ? name : null;
};

/** Translate one Objective-C type encoding fragment into a Ghidra C type name. */
export const objcEncodingToCType = (encoding: string): string | null => {
  if (encoding.length === 0) return null;
  const decoded = readType(encoding, 0);
  if (decoded === null || decoded.isVoid) return null;
  const next = skipDigits(encoding, decoded.next);
  return next === encoding.length ? decoded.cType : null;
};

/**
 * Translate one Objective-C method type encoding into a Ghidra C signature.
 * Unsupported encodings return null and must not be applied.
 */
export const objcEncodingToSignature = (
  encoding: string,
  selector: string,
): string | null => {
  const name = cIdentifier(selector);
  if (name === null || encoding.length === 0) return null;
  const returnType = readType(encoding, 0);
  if (returnType === null) return null;
  let cursor = skipDigits(encoding, returnType.next);
  const parameters: string[] = [];
  while (cursor < encoding.length) {
    const parameter = readType(encoding, cursor);
    if (parameter === null || parameter.isVoid) return null;
    parameters.push(parameter.cType);
    cursor = skipDigits(encoding, parameter.next);
  }
  if (cursor !== encoding.length) return null;
  const formals =
    parameters.length === 0
      ? "void"
      : parameters
          .map((type, index) => {
            const parameterName =
              index === 0 ? "self" : index === 1 ? "cmd" : `arg${index}`;
            return `${type} ${parameterName}`;
          })
          .join(", ");
  const signature = `${returnType.cType} ${name}(${formals})`;
  return signature.length <= 512 ? signature : null;
};
