# Quantum-Strand Viewer

This is a web-based viewer for analyzing the output of the `floss` tool's quantum-strand analysis. It allows for interactive filtering and exploration of extracted strings, tags, and structures from a binary file.

## Features

- Upload and parse `floss` quantum-strand JSON output.
- Filter strings by search term, minimum length, tags, and structures.
- Toggle display of columns (tags, encoding, offset/structure).
- Copy filtered strings to the clipboard.

## Development

To set up the development environment, first install the dependencies:

```bash
npm install
```

Then, run the development server:

```bash
npm run dev
```

This will start a local server, and you can view the application in your browser. The server supports Hot Module Replacement (HMR), so changes to the source code will be reflected live without a full page reload.

## Building

To build the application for production, run the following command:

```bash
npm run build
```

This will create a single, self-contained HTML file in the `dist` directory. This file can be opened directly in a browser or hosted on a web server.