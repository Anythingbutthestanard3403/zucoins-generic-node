import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ErrorBoundary, isChunkLoadError } from "./ErrorBoundary.js";

function Boom({ error }: { error: Error }): never {
  throw error;
}

afterEach(() => {
  cleanup();
});

describe("isChunkLoadError", () => {
  it("detects dynamic import failures", () => {
    expect(
      isChunkLoadError(new Error("Failed to fetch dynamically imported module: /assets/x.js")),
    ).toBe(true);
    expect(isChunkLoadError(new Error("Importing a module script failed."))).toBe(true);
    expect(isChunkLoadError(new Error("Loading chunk wallets-abc failed"))).toBe(true);
    expect(isChunkLoadError(new Error("Unexpected token '<'"))).toBe(false);
  });
});

describe("ErrorBoundary chunk recovery", () => {
  it("offers reload for chunk-load failures", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    render(
      <ErrorBoundary variant="inline">
        <Boom error={new Error("Failed to fetch dynamically imported module")} />
      </ErrorBoundary>,
    );
    expect(screen.getByRole("alert")).toHaveTextContent("Console update required");
    expect(screen.getByRole("button", { name: /Reload console/i })).toBeTruthy();
    spy.mockRestore();
  });

  it("keeps try-again for ordinary render errors", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    render(
      <ErrorBoundary variant="inline">
        <Boom error={new Error("null is not an object")} />
      </ErrorBoundary>,
    );
    expect(screen.getByRole("alert")).toHaveTextContent("Something went wrong");
    fireEvent.click(screen.getByRole("button", { name: /Try again/i }));
    spy.mockRestore();
  });
});
