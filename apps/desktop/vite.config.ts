import { readFile } from "node:fs/promises";
import type { Plugin } from "vite";
import { defineConfig } from "vitest/config";

/**
 * For trying the page in a browser: serves the sample report exactly as it is on disk. The
 * development server would otherwise rewrite it as one of its own pages, and the report's
 * content security policy rightly refuses a script that is not byte for byte the shipped one.
 */
function sampleReport(): Plugin {
  return {
    name: "sample-report",
    configureServer(server) {
      for (const name of ["sample-report", "relationships-report"]) {
        server.middlewares.use(`/${name}`, (_request, response) => {
          readFile(new URL(`./tests/fixtures/${name}.html`, import.meta.url)).then(
            (page) => {
              response.setHeader("Content-Type", "text/html; charset=utf-8");
              response.end(page);
            },
            () => {
              response.statusCode = 404;
              response.end("Make the sample first: npm run fixture");
            },
          );
        });
      }
    },
  };
}

// The page is loaded by the app from its own files, so every path is relative and nothing is
// inlined that the content security policy would have to make an exception for.
export default defineConfig({
  base: "./",
  clearScreen: false,
  plugins: [sampleReport()],
  server: { port: 1420, strictPort: true },
  build: { target: "safari15", assetsInlineLimit: 0, sourcemap: false },
  test: { environment: "node", include: ["tests/**/*.test.ts"] },
});
