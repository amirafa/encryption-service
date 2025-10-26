import { defineConfig } from "vite";
import path from "path";

export default defineConfig({
  build: {
    lib: {
      entry: path.resolve(__dirname, "src/EncryptionService.ts"),
      name: "EncryptionService",
      fileName: (format) => `encryption-service.${format}.js`,
    },
    rollupOptions: {
      external: [],
    },
    sourcemap: true,
  },
});