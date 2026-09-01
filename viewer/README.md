# FLOSS Graphical Viewer

This is a web-based viewer for analyzing the output of the `floss` tool. It allows for interactive filtering and exploration of extracted strings, tags, and structures from a binary file.

## Features

- Upload and parse `floss` JSON output.
- Filter strings by search term, minimum length, tags, and structures.
- Toggle display of columns (tags, encoding, offset/structure).
- Copy filtered strings to the clipboard.
- Download the viewer itself as a standalone HTML file for offline use (download icon in the header). The saved file is fully self-contained and can be opened directly in a browser without an internet connection. The file is named after the viewer version, the commit date, and the git commit it was built from (e.g. `floss-viewer-3.1.1-26-08-24-abc1234.html`).
- Preload results from `window.flossResults`. FLOSS `--html` fills this from the built `dist/index.html` template so the report opens with results already loaded. Leave it `null` for the hosted viewer and the Download-viewer copy.

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

To check your changes and build for production, run:

```bash
npm run lint
npm run build
```

This will create a single, self-contained HTML file in the `dist` directory. This file can be opened directly in a browser or hosted on a web server.