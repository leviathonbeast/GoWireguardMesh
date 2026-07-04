import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // Relative asset paths so the UI works if Traefik mounts it under a
  // path prefix rather than at the domain root.
  base: "./",
  server: {
    // `npm run dev` proxies API calls to a locally running control
    // plane, so the UI can be developed without rebuilding the Go binary.
    proxy: {
      "/api": "http://127.0.0.1:8080",
      "/enroll": "http://127.0.0.1:8080",
    },
  },
});
