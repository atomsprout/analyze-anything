import { describe, expect, it } from "vitest";
import { sourceRoots } from "../src/source-roots";

describe("Windows logical source roots", () => {
  it("ignores blank draft rows and canonicalizes assignments deterministically", () => {
    expect(sourceRoots([{ inf: "", root: "" }, { inf: "Z.INF", root: "." }, { inf: "Pkg/A.inf", root: "Pkg" }, { inf: "pkg/a.INF", root: "PKG" }])).toEqual([
      { inf: "pkg/a.inf", root: "pkg" }, { inf: "z.inf", root: "." },
    ]);
  });

  it("rejects conflicting assignments without guessing a root", () => {
    expect(() => sourceRoots([{ inf: "A.inf", root: "." }, { inf: "a.INF", root: "pkg" }])).toThrow();
  });

  it("rejects host paths and unsupported logical path profiles", () => {
    for (const root of ["", "C:/drivers", "\\\\host\\share", "/drivers", "../drivers", "a/./b", "%windir%", "CON.txt", "a ", "a.", "a//b", "驱动", "a~1", "a\\b", "a".repeat(256)]) {
      expect(() => sourceRoots([{ inf: "driver.inf", root }]), root).toThrow();
    }
    for (const inf of ["", "driver.sys", "../driver.inf", "C:/driver.inf", "NUL.inf"]) {
      expect(() => sourceRoots([{ inf, root: "." }]), inf).toThrow();
    }
  });

  it("bounds assignments and logical paths before sending them to the worker", () => {
    expect(() => sourceRoots(Array.from({ length: 33 }, (_, n) => ({ inf: `${n}.inf`, root: "." })))).toThrow();
    expect(() => sourceRoots([{ inf: "driver.inf", root: Array(513).fill("a").join("/") }])).toThrow();
    expect(() => sourceRoots([{ inf: "driver.inf", root: Array(42).fill("a".repeat(200)).join("/") }])).toThrow();
  });
});
