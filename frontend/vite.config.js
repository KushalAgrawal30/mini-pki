import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev: Vite serves the UI and proxies API/CA calls to the Flask HTTPS server.
const backend = { target: 'https://127.0.0.1:8443', secure: false }

export default defineConfig({
  plugins: [react()],
  server: { proxy: { '/api': backend, '/ca': backend, '/crl.pem': backend, '/cert': backend } },
})
