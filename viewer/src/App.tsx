import React, { useState, useCallback, useMemo, useRef, useEffect, useDeferredValue } from 'react';
import { useDropzone } from 'react-dropzone';
import './App.css';
import { type ResultDocument, type ResultLayout, type ResultString, type Analysis, type Strings } from './types';
import previewData from './pma0303_floss.json';

const NOISY_TAGS = ['#common', '#duplicate', '#code', '#reloc', '#code-junk'];

interface DisplayOptions {
  showTags: boolean;
  showEncoding: boolean;
  showOffsetAndStructure: boolean;
}

const subsequenceMatch = (query: string, target: string): boolean => {
  const qlen = query.length;
  if (qlen === 0) return true;
  let qi = 0;
  for (let ti = 0; ti < target.length && qi < qlen; ti++) {
    if (query.charCodeAt(qi) === target.charCodeAt(ti)) qi++;
  }
  return qi === qlen;
};

const ROW_HEIGHT = 26;
const HEADER_HEIGHT = 35;
const OVERSCAN = 10;

type VirtualRow =
  | { kind: 'header'; name: string }
  | { kind: 'string'; str: ResultString; alt: boolean };

const StringItem: React.FC<{
  str: ResultString;
  displayOptions: DisplayOptions;
  alt?: boolean;
  style?: React.CSSProperties;
}> = React.memo(({ str, displayOptions, alt, style }) => {
  const getStyleClass = () => {
    const { tags } = str;
    if (tags.includes('#capa')) return 'highlight';

    if (tags.some(t => NOISY_TAGS.includes(t))) return 'mute';

    return '';
  };

  const styleClass = getStyleClass();

  const offsetHex = str.offset.toString(16).padStart(8, '0');
  const firstDigitIndex = offsetHex.search(/[^0]/);
  const zeroPart = firstDigitIndex === -1 ? offsetHex : offsetHex.substring(0, firstDigitIndex);
  const digitPart = firstDigitIndex === -1 ? '' : offsetHex.substring(firstDigitIndex);

  return (
    <div
      className={`string-view ${alt ? 'string-view--alt' : ''}`}
      style={style}
      title={str.string}
    >
      <span className={`string-content ${styleClass}`}>{str.string}</span>
      {displayOptions.showTags && <span className={`string-tags ${styleClass}`}>{str.tags.join(' ')}</span>}
      {displayOptions.showEncoding && <span className="string-encoding">{str.encoding === 'unicode' ? 'U' : ''}</span>}
      {displayOptions.showOffsetAndStructure && (
        <span className="string-offset-structure">
          <span className="offset-zeros">{zeroPart}</span>
          <span className="offset-digits">{digitPart}</span>
          {str.structure && <span className="structure-name">/{str.structure}</span>}
        </span>
      )}
    </div>
  );
});

const VirtualList: React.FC<{ layout: ResultLayout; displayOptions: DisplayOptions }> = ({ layout, displayOptions }) => {
  const { rows, prefixes, totalHeight } = useMemo(() => {
    const rows: VirtualRow[] = [];
    const prefixes: number[] = [0];
    let alt = true;
    let total = 0;

    const push = (row: VirtualRow, height: number) => {
      rows.push(row);
      total += height;
      prefixes.push(total);
    };

    const walk = (l: ResultLayout) => {
      push({ kind: 'header', name: l.name }, HEADER_HEIGHT);
      for (const s of l.strings) {
        push({ kind: 'string', str: s, alt }, ROW_HEIGHT);
        alt = !alt;
      }
      for (const c of l.children) walk(c);
    };

    walk(layout);
    return { rows, prefixes, totalHeight: total };
  }, [layout]);

  const containerRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportH, setViewportH] = useState(0);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const update = () => {
      setScrollTop(el.scrollTop);
      setViewportH(el.clientHeight);
    };
    update();
    const ro = new ResizeObserver(update);
    ro.observe(el);
    el.addEventListener('scroll', update, { passive: true });
    return () => {
      ro.disconnect();
      el.removeEventListener('scroll', update);
    };
  }, []);

  const n = rows.length;
  let startIdx = 0;
  let lo = 0;
  let hi = n;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (prefixes[mid] <= scrollTop) lo = mid;
    else hi = mid - 1;
  }
  startIdx = lo;

  const endBottom = scrollTop + viewportH;
  let endIdx = startIdx;
  while (endIdx < n && prefixes[endIdx] < endBottom + OVERSCAN * ROW_HEIGHT) endIdx++;

  const visible: React.ReactNode[] = [];
  for (let i = Math.max(0, startIdx - OVERSCAN); i < endIdx; i++) {
    const row = rows[i];
    const top = prefixes[i];
    if (row.kind === 'header') {
      visible.push(
        <div key={i} className="layout-header" style={{ position: 'absolute', top, left: 0, right: 0 }}>
          {row.name}
        </div>
      );
    } else {
      visible.push(
        <StringItem
          key={i}
          str={row.str}
          displayOptions={displayOptions}
          alt={row.alt}
          style={{ position: 'absolute', top, left: 0, right: 0 }}
        />
      );
    }
  }

  return (
    <div className="virtual-list" ref={containerRef}>
      <div style={{ height: totalHeight, position: 'relative' }}>{visible}</div>
    </div>
  );
};

const CheckItem: React.FC<{ label: string; count?: number; checked: boolean; onChange: () => void }> = ({ label, count, checked, onChange }) => (
  <label className="check-item">
    <input type="checkbox" checked={checked} onChange={onChange} />
    <span className="check-box" />
    <span>{label}</span>
    {count !== undefined && <span className="check-count">{count}</span>}
  </label>
);

/** Extract just the filename from a full path */
const getFilename = (path: string): string => {
  const parts = path.replace(/\\/g, '/').split('/');
  return parts[parts.length - 1] || path;
};

/** Split a hash into fixed-width 32-char lines for clean rectangular display */
const chunkHash = (hash: string, charsPerLine = 32): string[] => {
  const lines: string[] = [];
  for (let i = 0; i < hash.length; i += charsPerLine) {
    lines.push(hash.substring(i, i + charsPerLine));
  }
  return lines;
};

const toNum = (v: unknown, d = 0): number => (typeof v === 'number' && Number.isFinite(v) ? v : d);
const toStr = (v: unknown, d = ''): string => (typeof v === 'string' ? v : d);

const normalizeString = (raw: unknown): ResultString | null => {
  if (typeof raw !== 'object' || raw === null) return null;
  const o = raw as Record<string, unknown>;
  if (typeof o.string !== 'string') return null;
  return {
    string: o.string,
    offset: toNum(o.offset),
    size: toNum(o.size),
    encoding: toStr(o.encoding),
    tags: Array.isArray(o.tags) ? o.tags.filter((t): t is string => typeof t === 'string') : [],
    structure: toStr(o.structure),
  };
};

const normalizeLayout = (raw: unknown): ResultLayout | null => {
  if (typeof raw !== 'object' || raw === null) return null;
  const o = raw as Record<string, unknown>;
  const strings = (Array.isArray(o.strings) ? o.strings.map(normalizeString) : []).filter(
    (s): s is ResultString => s !== null
  );
  const children = (Array.isArray(o.children) ? o.children.map(normalizeLayout) : []).filter(
    (c): c is ResultLayout => c !== null
  );
  return {
    name: toStr(o.name, 'section'),
    offset: toNum(o.offset),
    length: toNum(o.length),
    strings,
    children,
  };
};

const normalizeDocument = (raw: unknown): ResultDocument | null => {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null;
  const o = raw as Record<string, unknown>;
  if (!o.layout && !o.metadata) return null;

  const metaRaw = (typeof o.metadata === 'object' && o.metadata !== null ? o.metadata : {}) as Record<string, unknown>;
  const runRaw = (typeof metaRaw.runtime === 'object' && metaRaw.runtime !== null ? metaRaw.runtime : {}) as Record<string, unknown>;

  return {
    metadata: {
      file_path: toStr(metaRaw.file_path, 'unknown'),
      md5: toStr(metaRaw.md5),
      sha1: toStr(metaRaw.sha1),
      sha256: toStr(metaRaw.sha256),
      version: toStr(metaRaw.version),
      imagebase: toNum(metaRaw.imagebase),
      min_length: toNum(metaRaw.min_length),
      runtime: {
        start_date: toStr(runRaw.start_date),
        total: toNum(runRaw.total),
        vivisect: toNum(runRaw.vivisect),
        find_features: toNum(runRaw.find_features),
        static_strings: toNum(runRaw.static_strings),
        layout: toNum(runRaw.layout),
        tags: toNum(runRaw.tags),
        language_strings: toNum(runRaw.language_strings),
        stack_strings: toNum(runRaw.stack_strings),
        decoded_strings: toNum(runRaw.decoded_strings),
        tight_strings: toNum(runRaw.tight_strings),
      },
      language: toStr(metaRaw.language),
      language_version: toStr(metaRaw.language_version),
      language_selected: toStr(metaRaw.language_selected),
    },
    analysis: (typeof o.analysis === 'object' && o.analysis !== null ? o.analysis : {}) as Analysis,
    strings: (typeof o.strings === 'object' && o.strings !== null ? o.strings : {}) as Strings,
    layout: normalizeLayout(o.layout),
  };
};

export class ErrorBoundary extends React.Component<{ children: React.ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error) {
    console.error(error);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="crash-state">
          <div className="crash-inner">
            <p className="crash-title">Something went wrong</p>
            <p className="crash-sub">{String(this.state.error)}</p>
            <button className="btn-ghost" onClick={() => window.location.reload()}>Reload the viewer</button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

const App: React.FC = () => {
  const [data, setData] = useState<ResultDocument | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [minStringLength, setMinStringLength] = useState(0);
  const [selectedTags, setSelectedTags] = useState<string[]>([]);
  const [showUntagged, setShowUntagged] = useState(true);
  const [selectedStructures, setSelectedStructures] = useState<string[]>([]);
  const [showStringsWithoutStructure, setShowStringsWithoutStructure] = useState(true);
  const [displayOptions, setDisplayOptions] = useState<DisplayOptions>({
    showTags: true,
    showEncoding: true,
    showOffsetAndStructure: true,
  });
  const [copyFeedback, setCopyFeedback] = useState('');

  // Theme
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    const saved = localStorage.getItem('floss-viewer-theme');
    if (saved === 'light' || saved === 'dark') return saved;
    return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('floss-viewer-theme', theme);
  }, [theme]);

  // Resizable sidebar
  const [sidebarWidth, setSidebarWidth] = useState(360);
  const isDragging = useRef(false);
  const handleRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isDragging.current) return;
      e.preventDefault();
      const newWidth = Math.min(600, Math.max(260, e.clientX));
      setSidebarWidth(newWidth);
    };

    const handleMouseUp = () => {
      if (isDragging.current) {
        isDragging.current = false;
        document.body.classList.remove('resizing');
        handleRef.current?.classList.remove('dragging');
      }
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };
  }, []);

  const handleResizeStart = useCallback(() => {
    isDragging.current = true;
    document.body.classList.add('resizing');
    handleRef.current?.classList.add('dragging');
  }, []);

  const processData = useCallback((jsonData: ResultDocument) => {
    setData(jsonData);
    setSearchTerm('');
    setShowUntagged(true);
    setShowStringsWithoutStructure(true);
    setMinStringLength(jsonData.metadata.min_length);

    const allTags = new Set<string>();
    const allStructures = new Set<string>();
    const collect = (layout: ResultLayout) => {
      layout.strings.forEach(s => {
        s.tags.forEach(t => allTags.add(t));
        if (s.structure) {
          allStructures.add(s.structure);
        }
      });
      layout.children.forEach(collect);
    };
    if (jsonData.layout) {
      collect(jsonData.layout);
    }

    const defaultTags = Array.from(allTags).filter(
      tag => tag !== '#code' && tag !== '#reloc'
    );
    setSelectedTags(defaultTags);
    setSelectedStructures(Array.from(allStructures));
  }, [])

  // When FLOSS serves this viewer over its local server, the analysis results
  // are exposed at /results and the viewer loads them on its own. When that
  // fetch fails (static hosting, the dev server, or a plain file), keep the
  // preview and upload behavior.
  useEffect(() => {
    let cancelled = false;
    fetch('/results')
      .then((r) => {
        if (!r.ok) throw new Error(`no results available (${r.status})`);
        return r.json();
      })
      .then((json) => {
        if (cancelled) return;
        const normalized = normalizeDocument(json);
        if (normalized) processData(normalized);
      })
      .catch(() => {
        // not served by FLOSS: fall back to preview/upload
      });
    return () => {
      cancelled = true;
    };
  }, [processData]);

  const onDrop = useCallback((acceptedFiles: File[]) => {
    const file = acceptedFiles[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      let normalized: ResultDocument | null = null;
      try {
        normalized = normalizeDocument(JSON.parse(content));
      } catch (error) {
        console.error("Error parsing JSON:", error);
      }
      if (!normalized) {
        alert("Failed to parse JSON file. Expected a FLOSS result document.");
        return;
      }
      processData(normalized);
    };
    reader.onerror = () => {
      console.error("Error reading file:", file.name);
      alert("Failed to read the file.");
    };
    reader.readAsText(file);
  }, [processData]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    noClick: true,
    noKeyboard: true,
    accept: { 'application/json': ['.json'] },
  });

  const handleSearchChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setSearchTerm(event.target.value);
  };

  const handleMinLengthChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const value = event.target.value;
    setMinStringLength(value === '' ? 0 : parseInt(value, 10));
  };

  const handleTagChange = (tag: string) => {
    setSelectedTags(prev =>
      prev.includes(tag) ? prev.filter(t => t !== tag) : [...prev, tag]
    );
  };

  const handleStructureChange = (structure: string) => {
    setSelectedStructures(prev =>
      prev.includes(structure) ? prev.filter(s => s !== structure) : [...prev, structure]
    );
  };

  const handleDisplayOptionChange = (option: keyof DisplayOptions) => {
    setDisplayOptions(prev => ({ ...prev, [option]: !prev[option] }));
  };

  const tagInfo = useMemo(() => {
    if (!data) return { availableTags: [], tagCounts: {}, untaggedCount: 0, totalStringCount: 0 };

    const counts: { [key: string]: number } = {};
    let untaggedCount = 0;
    let totalStringCount = 0;
    const collect = (layout: ResultLayout) => {
      totalStringCount += layout.strings.length;
      for (const s of layout.strings) {
        if (s.tags.length === 0) {
          untaggedCount++;
        } else {
          for (const tag of s.tags) {
            counts[tag] = (counts[tag] || 0) + 1;
          }
        }
      }
      for (const child of layout.children) {
        collect(child);
      }
    };
    if (data.layout) {
      collect(data.layout);
    }

    return {
      availableTags: Object.keys(counts).sort(),
      tagCounts: counts,
      untaggedCount,
      totalStringCount,
    };
  }, [data]);

  const structureInfo = useMemo(() => {
    if (!data) return { availableStructures: [], structureCounts: {}, withoutStructureCount: 0 };

    const counts: { [key: string]: number } = {};
    let withoutStructureCount = 0;
    const collect = (layout: ResultLayout) => {
      for (const s of layout.strings) {
        if (!s.structure) {
          withoutStructureCount++;
        } else {
          counts[s.structure] = (counts[s.structure] || 0) + 1;
        }
      }
      for (const child of layout.children) {
        collect(child);
      }
    };
    if (data.layout) {
      collect(data.layout);
    }

    return {
      availableStructures: Object.keys(counts).sort(),
      structureCounts: counts,
      withoutStructureCount,
    };
  }, [data]);


  const handleSelectAll = () => {
    setSelectedTags(tagInfo.availableTags);
    setShowUntagged(true);
  };

  const handleSelectNone = () => {
    setSelectedTags([]);
    setShowUntagged(false);
  };

  const handleFocusView = () => {
    const focusedTags = tagInfo.availableTags.filter(
      tag => !NOISY_TAGS.includes(tag)
    );
    setSelectedTags(focusedTags);
    setShowUntagged(true);
  };

  const handlePreview = () => {
    // The JSON is now imported directly, so we can just use it.
    // The type assertion is safe because we trust the local file.
    processData(previewData as ResultDocument);
  };

  const lowercaseMap = useMemo(() => {
    const map = new Map<ResultString, string>();
    const walk = (layout: ResultLayout) => {
      layout.strings.forEach(s => map.set(s, s.string.toLowerCase()));
      layout.children.forEach(walk);
    };
    if (data?.layout) walk(data.layout);
    return map;
  }, [data]);

  const deferredSearchTerm = useDeferredValue(searchTerm);

  const filteredLayout = useMemo(() => {
    if (!data) return null;
    if (!data.layout) return null;

    const filter = (layout: ResultLayout): ResultLayout | null => {
      const lowerCaseSearchTerm = deferredSearchTerm.toLowerCase();

      const filteredStrings = layout.strings.filter(s => {
        if (s.string.length < minStringLength) return false;

        const searchMatch = deferredSearchTerm === ''
          ? true
          : subsequenceMatch(lowerCaseSearchTerm, lowercaseMap.get(s) ?? s.string.toLowerCase());
        if (!searchMatch) return false;

        const tagMatch = s.tags.length === 0
          ? showUntagged
          : selectedTags.length === 0 ? false : s.tags.every(tag => selectedTags.includes(tag));
        if (!tagMatch) return false;

        const structureMatch = !s.structure
          ? showStringsWithoutStructure
          : selectedStructures.length === 0 ? false : selectedStructures.includes(s.structure);
        if (!structureMatch) return false;

        return true;
      });

      const filteredChildren = layout.children
        .map(filter)
        .filter((c): c is ResultLayout => c !== null);

      if (filteredStrings.length > 0 || filteredChildren.length > 0) {
        return {
          ...layout,
          strings: filteredStrings,
          children: filteredChildren,
        };
      }

      return null;
    };

    return filter(data.layout);
  }, [data, lowercaseMap, deferredSearchTerm, selectedTags, showUntagged, minStringLength, selectedStructures, showStringsWithoutStructure]);

  const visibleStringCount = useMemo(() => {
    if (!filteredLayout) return 0;
    let count = 0;
    const countStrings = (layout: ResultLayout) => {
      count += layout.strings.length;
      layout.children.forEach(countStrings);
    };
    countStrings(filteredLayout);
    return count;
  }, [filteredLayout]);

  const ignoredStringCount = tagInfo.totalStringCount - visibleStringCount;

  const handleCopyStrings = () => {
    if (!filteredLayout) return;

    const stringsToCopy: string[] = [];
    const collectStrings = (layout: ResultLayout) => {
      stringsToCopy.push(...layout.strings.map(s => s.string));
      layout.children.forEach(collectStrings);
    };
    collectStrings(filteredLayout);

    navigator.clipboard.writeText(stringsToCopy.join('\n')).then(() => {
      setCopyFeedback('Copied!');
      setTimeout(() => setCopyFeedback(''), 2000);
    }, (err) => {
      console.error('Could not copy text: ', err);
      setCopyFeedback('Failed to copy.');
      setTimeout(() => setCopyFeedback(''), 2000);
    });
  };

  return (
    <div className={isDragActive ? 'App drag-active' : 'App'} {...getRootProps()}>
      {/* ---- Sidebar ---- */}
      <div className="sidebar" style={{ width: sidebarWidth }}>
        <div className="sidebar-header">
          <img className="app-logo" src="data:image/png;base64,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AMBwfPCDH6xHH3207TAAAAD2a6tWrWo7BIZsxYoV3ba4XWKG6aVmBiYAAABgP3LmmWe2HQIAAADsdwxMzD4rV67stuURj+QAAAAAAAAAgAkceOCB3bZsHUYc9K6HIZctBiYAAAAAAAAAYAI9NN8fGkYc9KZpml6GXB4yMAEAAAAAAAAAE+jltoJhxEFvli1bViMjI922Pdx1BwAAAAAAAACz34knnlhr165tO4yfkKQ+9alPtR3GhHq4rWDzIP6555xzTm3atGkQf/S0/Mu//EvdfffdbYfxpHqoV1XVQwYmAAAAAAAAAOaAc889t84999y2w/gJ27dvn/EDEytXruy2ZSADE+9///sH8cdO26/+6q/O6IGJVatW9bJts0dyAAAAAAAAANCabdu2tR1CVz004AcyMDFTPfroo22HMKFeBybcMAEAAACzx6aq+p9tBwEAAEBPdrUdwGwxGwYmDj/88G5bHh5GHDPFI4880nYIE+qhXqmqhw1MAAAAwCzRNM1dVfXatuMAAACAfprpAxMLFy6sFStWdNv24DBimSlm+g0Thx12WLctm5qm2euRHAAAAAAAAAC0ZuvWrW2HMKFDDz20mqbptu3eYcQyU8z0GyYOPfTQblvuraoyMAEAAAAAAABAax5+eGY/zaKH5ntV1X2DjmMm2b59e9shTKiHGybuqzIwAQAAAAAAAECL7rrrrrZDmFAPzfeqOTQwsWvXrtq8eXPbYUyoh5q5YQIAAAAAAACAdt19991thzChHprvO5um2TKMWGaCe+65p5K0HcaEer1hYmTwoQAAAAAAAAAwaE3TPKftGH5ckpGqerSqFjzZnpk+MHH44Yd32zKl2yWapvnXqmqm8vcOUpL3VNUfPtnr99577xCjmZojjzyy2xaP5AAAAAAAAABgoI6pCYYlqqruvPPOIYUyNcccc0y3LfcPI44hesZEL95zzz3DimNKli9fXgcddFC3bQYmAAAAAAAAABion+m24a677hpGHFN29NFHd9sysw8wecdO9OJMv2HiGc+YcN5jnzuqDEwAAAAAAAAAMDgTDkzs2rWrbr/99iGFMjU9NOA3DCOOYUgyrzq3gjyp//zP/xxSNFPT48DEbVUGJgAAAAAAAAAYnOdM9OItt9xSo6Ojw4pl0kZGRurII4/stm2/GZioquOratFEG7773e8OKZSp6WFg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" alt="FLOSS" />
          <div className="sidebar-header-buttons">
            <button
              className="btn-ghost"
              onClick={() => setTheme(t => t === 'light' ? 'dark' : 'light')}
              title={theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode'}
              aria-label={theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode'}
              style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: 32, padding: '7px 0' }}
            >
              {theme === 'light' ? (
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
                </svg>
              ) : (
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="5" />
                  <line x1="12" y1="1" x2="12" y2="3" />
                  <line x1="12" y1="21" x2="12" y2="23" />
                  <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
                  <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
                  <line x1="1" y1="12" x2="3" y2="12" />
                  <line x1="21" y1="12" x2="23" y2="12" />
                  <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
                  <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
                </svg>
              )}
            </button>
            <button className="btn-ghost" onClick={handlePreview}>Preview</button>
            <label htmlFor="file-upload" className="btn-ghost" style={{ cursor: 'pointer' }}>
              Upload
            </label>
            <input {...getInputProps()} id="file-upload" />
          </div>
        </div>

        <div className="sidebar-body">
          {data && (
            <>
              {/* Metadata */}
              <div className="metadata">
                <div className="meta-row">
                  <span className="meta-label">File</span>
                  <span className="meta-value" title={data.metadata.file_path}>{getFilename(data.metadata.file_path)}</span>
                </div>
                <div className="meta-row">
                  <span className="meta-label">MD5</span>
                  <span className="meta-value meta-hash">{chunkHash(data.metadata.md5).map((line, i) => <div key={i}>{line}</div>)}</span>
                </div>
                <div className="meta-row">
                  <span className="meta-label">SHA256</span>
                  <span className="meta-value meta-hash">{chunkHash(data.metadata.sha256).map((line, i) => <div key={i}>{line}</div>)}</span>
                </div>
                <div className="meta-row">
                  <span className="meta-label">Time</span>
                  <span className="meta-value">{new Date(data.metadata.runtime.start_date).toLocaleString()}</span>
                </div>
                <div className="meta-row">
                  <span className="meta-label">Ver</span>
                  <span className="meta-value">{data.metadata.version}</span>
                </div>
              </div>

              {/* Search */}
              <div className="search-section">
                <div className="search-row">
                  <input
                    type="search"
                    placeholder="Search..."
                    className="search-input"
                    value={searchTerm}
                    onChange={handleSearchChange}
                  />
                  <div className="min-length-group">
                    <span className="min-length-label">Min</span>
                    <input
                      className="min-length-input"
                      type="number"
                      value={minStringLength}
                      onChange={handleMinLengthChange}
                      min="0"
                      onWheel={(e) => {
                        e.preventDefault();
                        setMinStringLength(prev => Math.max(0, prev + (e.deltaY < 0 ? 1 : -1)));
                      }}
                    />
                  </div>
                </div>
              </div>

              {/* Tags Filter */}
              <div className="filter-section">
                <div className="filter-section-header">
                  <span className="filter-section-title">Tags</span>
                  <div className="filter-actions">
                    <button className="filter-action-btn" onClick={handleSelectAll}>All</button>
                    <button className="filter-action-btn" onClick={handleSelectNone}>None</button>
                    <button className="filter-action-btn" onClick={handleFocusView}>Focus</button>
                  </div>
                </div>
                <div className="filter-items">
                  {tagInfo.availableTags.map(tag => (
                    <CheckItem
                      key={tag}
                      label={tag}
                      count={tagInfo.tagCounts[tag]}
                      checked={selectedTags.includes(tag)}
                      onChange={() => handleTagChange(tag)}
                    />
                  ))}
                  {tagInfo.untaggedCount > 0 && (
                    <CheckItem
                      key="untagged"
                      label="(untagged)"
                      count={tagInfo.untaggedCount}
                      checked={showUntagged}
                      onChange={() => setShowUntagged(p => !p)}
                    />
                  )}
                </div>
              </div>

              {/* Structures Filter */}
              <div className="filter-section">
                <div className="filter-section-header">
                  <span className="filter-section-title">Structures</span>
                </div>
                <div className="filter-items">
                  {structureInfo.availableStructures.map(structure => (
                    <CheckItem
                      key={structure}
                      label={structure}
                      count={structureInfo.structureCounts[structure]}
                      checked={selectedStructures.includes(structure)}
                      onChange={() => handleStructureChange(structure)}
                    />
                  ))}
                  {structureInfo.withoutStructureCount > 0 && (
                    <CheckItem
                      key="no-structure"
                      label="(none)"
                      count={structureInfo.withoutStructureCount}
                      checked={showStringsWithoutStructure}
                      onChange={() => setShowStringsWithoutStructure(p => !p)}
                    />
                  )}
                </div>
              </div>

              {/* Display Columns */}
              <div className="filter-section">
                <div className="filter-section-header">
                  <span className="filter-section-title">Columns</span>
                </div>
                <div className="filter-items">
                  <CheckItem label="Tags" checked={displayOptions.showTags} onChange={() => handleDisplayOptionChange('showTags')} />
                  <CheckItem label="Encoding" checked={displayOptions.showEncoding} onChange={() => handleDisplayOptionChange('showEncoding')} />
                  <CheckItem label="Offset & Structure" checked={displayOptions.showOffsetAndStructure} onChange={() => handleDisplayOptionChange('showOffsetAndStructure')} />
                </div>
              </div>
            </>
          )}
        </div>

        {/* Sidebar Footer */}
        {data && (
          <div className="sidebar-footer">
            <span className="string-count">
              <strong>{visibleStringCount}</strong>&nbsp;/&nbsp;{tagInfo.totalStringCount}
              {ignoredStringCount > 0 && (
                <>
                  &nbsp;·&nbsp;<span className="string-count-ignored">{ignoredStringCount} ignored</span>
                </>
              )}
            </span>
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <button className="btn-copy" onClick={handleCopyStrings}>Copy</button>
              {copyFeedback && <span className="copy-feedback">{copyFeedback}</span>}
            </div>
          </div>
        )}
      </div>

      {/* ---- Resize Handle ---- */}
      <div
        ref={handleRef}
        className="resize-handle"
        onMouseDown={handleResizeStart}
      />

      {/* ---- Main Content ---- */}
      <div className="main-content">
        {!data ? (
          <div className="welcome-state">
            <div className="welcome-inner">
              <p className="welcome-title">FLOSS Graphical Viewer</p>
              <p className="welcome-sub">Drag a JSON file or use the upload button</p>
            </div>
          </div>
        ) : filteredLayout ? (
          <VirtualList layout={filteredLayout} displayOptions={displayOptions} />
        ) : (
          <div className="welcome-state">
            <div className="welcome-inner">
              <p className="welcome-title">No matches</p>
              <p className="welcome-sub">Try adjusting your search or filter settings</p>
            </div>
          </div>
        )}
      </div>

      {isDragActive && (
        <div className="drop-overlay">
          <div className="drop-overlay-inner">
            <p className="drop-overlay-title">Drop JSON file to load</p>
            <p className="drop-overlay-sub">Drop to load a FLOSS JSON result</p>
          </div>
        </div>
      )}
    </div>
  );
};

export default App;
