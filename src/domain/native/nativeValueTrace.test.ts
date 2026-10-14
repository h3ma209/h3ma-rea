import { describe, expect, it } from "vitest";

import { sliceNativeValueGraph } from "./nativeValueTrace.js";

const operation = (id: string, address: string) => ({
  id,
  operation: { address },
});

describe("sliceNativeValueGraph", () => {
  const nodes = [
    operation("def", "0x1000"),
    operation("use", "0x1004"),
    operation("later", "0x1008"),
  ];
  const edges = [
    { source: "def", target: "use" },
    { source: "use", target: "later" },
  ];

  it("walks uses forward from an interior address", () => {
    const sliced = sliceNativeValueGraph(nodes, edges, "0x1004", "forward");
    expect(sliced.matched).toBe(true);
    expect(sliced.nodes.map((node) => node.id)).toEqual(["use", "later"]);
    expect(sliced.edges).toEqual([{ source: "use", target: "later" }]);
  });

  it("walks definitions backward and reports a missing address", () => {
    const sliced = sliceNativeValueGraph(nodes, edges, "1004", "backward");
    expect(sliced.nodes.map((node) => node.id)).toEqual(["def", "use"]);
    expect(sliceNativeValueGraph(nodes, edges, "0x1", "forward").matched).toBe(
      false,
    );
  });
});