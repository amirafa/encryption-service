import { defineConfig } from "vite";
import dts from "vite-plugin-dts";

export default defineConfig({
    plugins: [dts({ insertTypesEntry: true, outDir: "dist" })],
    build: {
        lib: {
            entry: "src/encryption-service.ts",
            name: "EncryptionService",
            fileName: (format) => `encryption-service.${format}.js`,
            formats: ["es", "cjs"],
        },
        rollupOptions: {
            external: ["crypto"],
        },
    },
});
