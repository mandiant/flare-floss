import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import { viteSingleFile } from 'vite-plugin-singlefile'

const publicDir = fileURLToPath(new URL('./public', import.meta.url))

// Inline the favicon as a data URI so the downloaded standalone HTML
// stays fully self-contained when opened offline via file://.
const inlineFavicon = (): Plugin => ({
  name: 'inline-favicon',
  apply: 'build',
  transformIndexHtml(html) {
    const dataUri = `data:image/png;base64,${readFileSync(join(publicDir, 'favicon.png')).toString('base64')}`
    return html.replace('href="favicon.png"', `href="${dataUri}"`)
  },
})

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), viteSingleFile(), inlineFavicon()],
})