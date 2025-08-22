import React, { useState, useCallback, useMemo } from 'react';
import { useDropzone } from 'react-dropzone';
import './App.css';
import { type ResultDocument, type ResultLayout, type ResultString } from './types';
import previewData from './pma0303_qs.json';

interface DisplayOptions {
  showTags: boolean;
  showEncoding: boolean;
  showOffsetAndStructure: boolean;
}

const StringItem: React.FC<{ 
  str: ResultString; 
  displayOptions: DisplayOptions;
  onAddTag: (offset: number, tag: string) => void;
}> = ({ str, displayOptions, onAddTag }) => {
  const [showTagInput, setShowTagInput] = useState(false);
  const [newTag, setNewTag] = useState('');

  const getStyleClass = () => {
    const { tags } = str;
    if (tags.includes('#capa')) return 'highlight';
    if (tags.includes('#common') || tags.includes('#duplicate')) return 'mute';
    return '';
  };

  const handleAddTag = () => {
    if (newTag.trim()) {
      const formattedTag = newTag.trim().startsWith('#') ? newTag.trim() : `#${newTag.trim()}`;
      onAddTag(str.offset, formattedTag);
      setNewTag('');
      setShowTagInput(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleAddTag();
    } else if (e.key === 'Escape') {
      setShowTagInput(false);
      setNewTag('');
    }
  };

  const styleClass = getStyleClass();

  const offsetHex = str.offset.toString(16).padStart(8, '0');
  const firstDigitIndex = offsetHex.search(/[^0]/);
  const zeroPart = firstDigitIndex === -1 ? offsetHex : offsetHex.substring(0, firstDigitIndex);
  const digitPart = firstDigitIndex === -1 ? '' : offsetHex.substring(firstDigitIndex);

  return (
    <div className="string-view">
      <span className={`string-content ${styleClass}`}>{JSON.stringify(str.string).slice(1, -1)}</span>
      {displayOptions.showTags && (
        <div className="tags-section">
          <button 
            className="add-tag-button" 
            onClick={() => setShowTagInput(true)}
            title="Add tag"
          >
            +
          </button>
          <span className={`string-tags ${styleClass}`}>
            {showTagInput && (
              <input
                type="text"
                className="tag-input"
                value={newTag}
                onChange={(e) => setNewTag(e.target.value)}
                onKeyDown={handleKeyPress}
                onBlur={() => setShowTagInput(false)}
                placeholder="Enter tag..."
                autoFocus
              />
            )}
            {str.tags.join(' ')}
          </span>
        </div>
      )}
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

const Layout: React.FC<{ 
  layout: ResultLayout; 
  displayOptions: DisplayOptions;
  onAddTag: (offset: number, tag: string) => void;
}> = ({ layout, displayOptions, onAddTag }) => {
  return (
    <div className="layout">
      <div className="layout-header">{layout.name}</div>
      <div className="layout-content">
        {layout.strings.map((str, index) => (
          <StringItem 
            key={index} 
            str={str} 
            displayOptions={displayOptions} 
            onAddTag={onAddTag}
          />
        ))}
        {layout.children.map((child, index) => (
          <Layout key={index} layout={child} displayOptions={displayOptions} onAddTag={onAddTag} />
        ))}
      </div>
    </div>
  );
};

const App: React.FC = () => {
  const [data, setData] = useState<ResultDocument | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedTags, setSelectedTags] = useState<string[]>([]);
  const [showUntagged, setShowUntagged] = useState(true);
  const [displayOptions, setDisplayOptions] = useState<DisplayOptions>({
    showTags: true,
    showEncoding: true,
    showOffsetAndStructure: true,
  });
  const [copyFeedback, setCopyFeedback] = useState('');

  const processData = (jsonData: ResultDocument) => {
      setData(jsonData);
      setSearchTerm('');
      setShowUntagged(true);

      const allTags = new Set<string>();
      const collectTags = (layout: ResultLayout) => {
        layout.strings.forEach(s => s.tags.forEach(t => allTags.add(t)));
        layout.children.forEach(collectTags);
      };
      collectTags(jsonData.layout);

      const defaultTags = Array.from(allTags).filter(
        tag => tag !== '#code' && tag !== '#reloc'
      );
      setSelectedTags(defaultTags);
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

  const handleTagChange = (tag: string) => {
    setSelectedTags(prev =>
      prev.includes(tag) ? prev.filter(t => t !== tag) : [...prev, tag]
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
    collect(data.layout);

    return {
      availableTags: Object.keys(counts).sort(),
      tagCounts: counts,
      untaggedCount,
      totalStringCount,
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

  const handleAddTag = (offset: number, tag: string) => {
    if (!data) return;
    
    // Create a deep copy of the data to modify
    const updatedData = JSON.parse(JSON.stringify(data));
    
    // Find and update the string with the specified offset
    const updateLayout = (layout: ResultLayout): boolean => {
      for (let i = 0; i < layout.strings.length; i++) {
        if (layout.strings[i].offset === offset) {
          if (!layout.strings[i].tags.includes(tag)) {
            layout.strings[i].tags.push(tag);
          }
          return true;
        }
      }
      for (const child of layout.children) {
        if (updateLayout(child)) {
          return true;
        }
      }
      return false;
    };
    
    updateLayout(updatedData.layout);
    setData(updatedData);
  };

  const filteredLayout = useMemo(() => {
    if (!data) return null;

    const filter = (layout: ResultLayout): ResultLayout | null => {
      const lowerCaseSearchTerm = searchTerm.toLowerCase();

      const filteredStrings = layout.strings.filter(s => {
        const searchMatch = s.string.toLowerCase().includes(lowerCaseSearchTerm);
        if (!searchMatch) return false;

        const isUntagged = s.tags.length === 0;
        if (isUntagged) {
          return showUntagged;
        } else {
          if (selectedTags.length === 0) return false;
          return s.tags.some(tag => selectedTags.includes(tag));
        }
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
  }, [data, searchTerm, selectedTags, showUntagged]);

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
      <div className="controls">
        <div className="app-header">
          <h1 className="app-title">Quantumstrand Viewer</h1>
          <div className="app-header-buttons">
            <button className="preview-button" onClick={handlePreview}>Preview PMA03-03.exe</button>
            <div className="file-upload-area">
              <label htmlFor="file-upload" className="file-upload-label">
                Upload JSON
              </label>
              <input {...getInputProps()} id="file-upload" />
            </div>
          </div>
        </div>

        {data && (
          <>
            <div className="metadata">
              <p><strong>Path:</strong> {data.meta.sample.path}</p>
              <p><strong>MD5:</strong> {data.meta.sample.md5}</p>
              <p><strong>SHA256:</strong> {data.meta.sample.sha256}</p>
              <p><strong>Timestamp:</strong> {new Date(data.meta.timestamp).toLocaleString()}</p>
              <p><strong>Minimum String Length:</strong> {data.meta.min_str_len}</p>
              <p><strong>Version:</strong> {data.meta.version}</p>
            </div>

            <div className="filters-container">
                <div className="filter-group">
                    <div className="filter-group-header">Tags</div>
                    <div className="tag-actions">
                        <button onClick={handleSelectAll}>Select All</button>
                        <button onClick={handleSelectNone}>Select None</button>
                        <button onClick={handleFocusView}>Focus View</button>
                    </div>
                    <div className="filter-group-content">
                      {tagInfo.availableTags.map(tag => (
                        <label key={tag}>
                          <input
                            type="checkbox"
                            checked={selectedTags.includes(tag)}
                            onChange={() => handleTagChange(tag)}
                          />
                          {tag} ({tagInfo.tagCounts[tag]})
                        </label>
                      ))}
                      {tagInfo.untaggedCount > 0 && (
                        <label key="untagged">
                          <input
                            type="checkbox"
                            checked={showUntagged}
                            onChange={() => setShowUntagged(p => !p)}
                          />
                          (untagged) ({tagInfo.untaggedCount})
                        </label>
                      )}
                    </div>
                </div>
                <div className="filter-group">
                    <div className="filter-group-header">Show Columns</div>
                    <div className="filter-group-content">
                        <label>
                            <input type="checkbox" checked={displayOptions.showTags} onChange={() => handleDisplayOptionChange('showTags')} /> Tags
                        </label>
                        <label>
                            <input type="checkbox" checked={displayOptions.showEncoding} onChange={() => handleDisplayOptionChange('showEncoding')} /> Encoding
                        </label>
                        <label>
                            <input type="checkbox" checked={displayOptions.showOffsetAndStructure} onChange={() => handleDisplayOptionChange('showOffsetAndStructure')} /> Offset & Structure
                        </label>
                    </div>
                </div>
            </div>

            <input
              type="search"
              placeholder="Search strings..."
              className="search-bar"
              value={searchTerm}
              onChange={handleSearchChange}
            />
            <div className="actions-bar">
                <div className="string-counts">
                  Showing {visibleStringCount} of {tagInfo.totalStringCount} strings
                </div>
                <div>
                    <button className="copy-button" onClick={handleCopyStrings}>Copy Strings</button>
                    {copyFeedback && <span className="copy-feedback">{copyFeedback}</span>}
                </div>
            </div>
          </>
        )}
      </div>
      <div className="results-container">
        {!data ? (
            <div className="welcome-message">Drop a JSON file or use the upload button to get started.</div>
        ) : filteredLayout ? (
          <Layout layout={filteredLayout} displayOptions={displayOptions} onAddTag={handleAddTag} />
        ) : (
            <div className="welcome-message">No strings found matching your search and tag filters.</div>
        )}
      </div>
    </div>
  );
};

export default App;
