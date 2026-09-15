/// <reference types="vite/client" />

export {};

declare global {
  interface Window {
    /** Preloaded FLOSS result document; null/undefined shows the upload screen. */
    flossResults?: unknown;
  }
}
