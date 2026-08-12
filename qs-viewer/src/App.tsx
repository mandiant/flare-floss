import React, { useState, useCallback, useMemo, useRef, useEffect } from 'react';
import { useDropzone } from 'react-dropzone';
import './App.css';
import { type ResultDocument, type ResultLayout, type ResultString } from './types';
import previewData from './pma_0303.json';

interface DisplayOptions {
  showTags: boolean;
  showEncoding: boolean;
  showOffsetAndStructure: boolean;
}

const StringItem: React.FC<{ str: ResultString; displayOptions: DisplayOptions }> = ({ str, displayOptions }) => {
  const getStyleClass = () => {
    const { tags } = str;
    if (tags.includes('#capa')) return 'highlight';
    if (tags.includes('#common') || tags.includes('#duplicate')) return 'mute';
    return '';
  };

  const styleClass = getStyleClass();

  const offsetHex = str.offset.toString(16).padStart(8, '0');
  const firstDigitIndex = offsetHex.search(/[^0]/);
  const zeroPart = firstDigitIndex === -1 ? offsetHex : offsetHex.substring(0, firstDigitIndex);
  const digitPart = firstDigitIndex === -1 ? '' : offsetHex.substring(firstDigitIndex);

  return (
    <div className="string-view">
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
};

const Layout: React.FC<{ layout: ResultLayout; displayOptions: DisplayOptions }> = ({ layout, displayOptions }) => {
  return (
    <div className="layout">
      <div className="layout-header">{layout.name}</div>
      <div className="layout-content">
        {layout.strings.map((str, index) => (
          <StringItem key={index} str={str} displayOptions={displayOptions} />
        ))}
        {layout.children.map((child, index) => (
          <Layout key={index} layout={child} displayOptions={displayOptions} />
        ))}
      </div>
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
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const content = e.target?.result as string;
          const jsonData: ResultDocument = JSON.parse(content);
          processData(jsonData);
        } catch (error) {
          console.error("Error parsing JSON:", error);
          alert("Failed to parse JSON file.");
        }
      };
      reader.readAsText(file);
    }
  }, []);

  const { getRootProps, getInputProps } = useDropzone({
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
    const noisyTags = ['#code', '#code-junk', '#duplicate', '#reloc'];
    const focusedTags = tagInfo.availableTags.filter(
      tag => !noisyTags.includes(tag)
    );
    setSelectedTags(focusedTags);
    setShowUntagged(true);
  };

  const handlePreview = () => {
    // The JSON is now imported directly, so we can just use it.
    // The type assertion is safe because we trust the local file.
    processData(previewData as ResultDocument);
  };

  const filteredLayout = useMemo(() => {
    if (!data) return null;
    if (!data.layout) return null;

    const filter = (layout: ResultLayout): ResultLayout | null => {
      const lowerCaseSearchTerm = searchTerm.toLowerCase();

      const filteredStrings = layout.strings.filter(s => {
        if (s.string.length < minStringLength) return false;

        const searchMatch = s.string.toLowerCase().includes(lowerCaseSearchTerm);
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
  }, [data, searchTerm, selectedTags, showUntagged, minStringLength, selectedStructures, showStringsWithoutStructure]);

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
    <div className="App" {...getRootProps()}>
      {/* ---- Sidebar ---- */}
      <div className="sidebar" style={{ width: sidebarWidth }}>
        <div className="sidebar-header">
          <h1 className="app-title">FLOSS</h1>
          <div className="sidebar-header-buttons">
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
          <Layout layout={filteredLayout} displayOptions={displayOptions} />
        ) : (
          <div className="welcome-state">
            <div className="welcome-inner">
              <p className="welcome-title">No matches</p>
              <p className="welcome-sub">Try adjusting your search or filter settings</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default App;
