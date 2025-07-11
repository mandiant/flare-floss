import React, { useState, useCallback, useMemo } from 'react';
import { useDropzone } from 'react-dropzone';
import './App.css';
import { type ResultDocument, type ResultLayout, type ResultString } from './types';

const StringItem: React.FC<{ str: ResultString }> = ({ str }) => {
  const offsetStructure = `${str.offset.toString(16).padStart(8, '0')}${str.structure ? `/${str.structure}` : ''}`;
  return (
    <div className="string-view">
      <span className="string-content">{JSON.stringify(str.string).slice(1, -1)}</span>
      <span className="string-tags">{str.tags.join(' ')}</span>
      <span className="string-encoding">{str.encoding === 'unicode' ? 'U' : ''}</span>
      <span className="string-offset-structure">{offsetStructure}</span>
    </div>
  );
};

const Layout: React.FC<{ layout: ResultLayout }> = ({ layout }) => {
  return (
    <div className="layout">
      <div className="layout-header">{layout.name}</div>
      <div className="layout-content">
        {layout.strings.map((str, index) => (
          <StringItem key={index} str={str} />
        ))}
        {layout.children.map((child, index) => (
          <Layout key={index} layout={child} />
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

  const onDrop = useCallback((acceptedFiles: File[]) => {
    const file = acceptedFiles[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const content = e.target?.result as string;
          const jsonData: ResultDocument = JSON.parse(content);
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

  return (
    <div className="App" {...getRootProps()}>
      <div className="controls">
        <div className="file-upload-area">
          <label htmlFor="file-upload" className="file-upload-label">
            Upload JSON
          </label>
          <input {...getInputProps()} id="file-upload" />
        </div>

        {data && (
          <>
            <div className="metadata">
              <p><strong>Path:</strong> {data.meta.sample.path}</p>
              <p><strong>SHA256:</strong> {data.meta.sample.sha256}</p>
              <p><strong>Version:</strong> {data.meta.version}</p>
              <p><strong>Timestamp:</strong> {new Date(data.meta.timestamp).toLocaleString()}</p>
            </div>

            <input
              type="search"
              placeholder="Search strings..."
              className="search-bar"
              value={searchTerm}
              onChange={handleSearchChange}
            />
            <div className="string-counts">
              Showing {visibleStringCount} of {tagInfo.totalStringCount} strings
            </div>
            <div className="tag-filter">
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
          </>
        )}
      </div>
      <div className="results-container">
        {!data ? (
            <div className="welcome-message">Drop a JSON file or use the upload button to get started.</div>
        ) : filteredLayout ? (
          <Layout layout={filteredLayout} />
        ) : (
            <div className="welcome-message">No strings found matching your search and tag filters.</div>
        )}
      </div>
    </div>
  );
};

export default App;
