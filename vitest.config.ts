import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    projects: [
      "packages/generic-node-contracts",
      "packages/node-core",
      "apps/generic-node",
      {
        test: {
          name: "consumers",
          passWithNoTests: true,
          include: [
            "packages/generic-node-consumer/src/**/*.{test,spec}.ts",
            "packages/consumer-example/src/**/*.{test,spec}.ts",
          ],
        },
      },
    ],
  },
});
