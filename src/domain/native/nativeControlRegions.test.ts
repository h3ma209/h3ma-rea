import { describe, expect, it } from "vitest";

import { regionKindForDecompilerBlock } from "./nativeControlRegions.js";

describe("regionKindForDecompilerBlock", () => {
  it("maps Ghidra structured parents", () => {
    expect(regionKindForDecompilerBlock("properif")).toBe("if");
    expect(regionKindForDecompilerBlock("ifelse")).toBe("if");
    expect(regionKindForDecompilerBlock("ifgoto")).toBe("if");
    expect(regionKindForDecompilerBlock("condition")).toBe("if");
    expect(regionKindForDecompilerBlock("whiledo")).toBe("loop");
    expect(regionKindForDecompilerBlock("dowhile")).toBe("loop");
    expect(regionKindForDecompilerBlock("infloop")).toBe("loop");
    expect(regionKindForDecompilerBlock("switch")).toBe("switch");
  });

  it("keeps a missing or listing parent unstructured", () => {
    expect(regionKindForDecompilerBlock("basic")).toBe("unstructured");
    expect(regionKindForDecompilerBlock("graph")).toBe("unstructured");
  });
});
