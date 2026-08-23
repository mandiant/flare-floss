import React, { useState, useCallback, useMemo, useRef, useEffect, useDeferredValue } from 'react';
import { useDropzone } from 'react-dropzone';
import './App.css';
import { type ResultDocument, type ResultLayout, type ResultString, type Analysis, type Strings } from './types';
import previewData from './pma0303_floss.json';
import { VIEWER_VERSION, VIEWER_COMMIT } from './generated/version';

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

const ThemeToggle: React.FC<{ theme: 'light' | 'dark'; onToggle: () => void; floating?: boolean }> = ({ theme, onToggle, floating }) => (
  <button
    className={`theme-toggle${floating ? ' theme-toggle--floating' : ''}`}
    onClick={onToggle}
    title={theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode'}
    aria-label={theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode'}
  >
    {theme === 'light' ? (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
      </svg>
    ) : (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
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
);

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

  const processData = (jsonData: ResultDocument) => {
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
  }

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
  }, []);

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

  const handleDownloadViewer = useCallback(async () => {
    let html: string | null = null;
    if (!import.meta.env.DEV) {
      try {
        const res = await fetch(window.location.href, { cache: 'no-store' });
        if (res.ok) html = await res.text();
      } catch {
        // fetch can fail on file:// or restricted origins; fall back to serializing the live DOM
      }
    }
    if (!html) {
      const clone = document.documentElement.cloneNode(true) as HTMLElement;
      const root = clone.querySelector('#root');
      if (root) root.innerHTML = '';
      clone.removeAttribute('data-theme');
      html = '<!doctype html>\n' + clone.outerHTML;
    }
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `floss-viewer-${VIEWER_VERSION}-${VIEWER_COMMIT}.html`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }, []);

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
      <ThemeToggle
        floating
        theme={theme}
        onToggle={() => setTheme(t => (t === 'light' ? 'dark' : 'light'))}
      />
      {/* ---- Sidebar ---- */}
      {data && (
        <>
          <div className="sidebar" style={{ width: sidebarWidth }}>
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
        <div className="sidebar-footer">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {data && (
              <span className="string-count">
                <strong>{visibleStringCount}</strong>&nbsp;/&nbsp;{tagInfo.totalStringCount}
                {ignoredStringCount > 0 && (
                  <>
                    &nbsp;·&nbsp;<span className="string-count-ignored">{ignoredStringCount} ignored</span>
                  </>
                )}
              </span>
            )}
          </div>
          {data && (
            <button className={`btn-copy${copyFeedback ? ' btn-copy--done' : ''}`} onClick={handleCopyStrings}>
              {copyFeedback || 'Copy'}
            </button>
          )}
        </div>
      </div>

      {/* ---- Resize Handle ---- */}
      <div
        ref={handleRef}
        className="resize-handle"
        onMouseDown={handleResizeStart}
      />
        </>
      )}

      {/* ---- Main Content ---- */}
      <div className="main-content">
        {!data ? (
          <div className="welcome-state">
            <div className="landing">
              <img className="landing-logo" src="/floss-logo.png" alt="FLOSS" />
              <a
                className="landing-title"
                href="https://github.com/mandiant/flare-floss"
                target="_blank"
                rel="noreferrer"
              >
                floss: FLARE Obfuscated String Solver
              </a>
              <p className="landing-desc">
                The FLOSS Graphical Viewer is a web-based tool to explore the strings extracted by
                FLOSS. It lets you interactively search, filter, and browse static, stack, tight,
                and decoded strings.
              </p>
              <div className="landing-actions">
                <label htmlFor="file-upload" className="btn-ghost" style={{ cursor: 'pointer' }}>
                  Upload
                </label>
                <input {...getInputProps()} id="file-upload" />
                <button className="btn-ghost" onClick={handlePreview} title="Load a sample floss results document">
                  Demo
                </button>
                <button
                  className="btn-ghost"
                  onClick={handleDownloadViewer}
                  title="Download this viewer as a standalone HTML file for offline use"
                  aria-label="Download this viewer as a standalone HTML file for offline use"
                >
                  <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                    <polyline points="7 10 12 15 17 10" />
                    <line x1="12" y1="15" x2="12" y2="3" />
                  </svg>
                  Download viewer
                </button>
              </div>
              <div className="landing-steps">
                <p className="landing-steps-title">New to floss? Follow these quick steps to get started:</p>
                <ol>
                  <li>
                    Install floss:
                    <ul>
                      <li>
                        download the latest{' '}
                        <a href="https://github.com/mandiant/flare-floss/releases/latest" target="_blank" rel="noreferrer">
                          standalone executable release
                        </a>
                      </li>
                      <li>
                        or run <code>pip install flare-floss</code>
                      </li>
                    </ul>
                  </li>
                  <li>
                    Analyze a sample and save the JSON results:
                    <br />
                    <code>floss -j /path/to/file &gt; results.json</code>
                  </li>
                  <li>Load the JSON results file into the viewer (drag and drop or Upload)</li>
                </ol>
                <p className="landing-steps-more">
                  For more detailed information, explore the{' '}
                  <a href="https://github.com/mandiant/flare-floss" target="_blank" rel="noreferrer">
                    floss GitHub repository
                  </a>
                  .
                </p>
              </div>
              <p className="landing-download">
                The download saves this viewer as a single HTML file that works offline, without
                an internet connection.
              </p>
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
