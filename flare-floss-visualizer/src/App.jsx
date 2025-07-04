import React, { useState, useEffect } from 'react';
import Layout from './components/Layout';
import TagFilter from './components/TagFilter';
import './App.css';

function App() {
  const [data, setData] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [enabledTags, setEnabledTags] = useState(new Set());
  const [allTags, setAllTags] = useState([]);
  const [fileName, setFileName] = useState('');

  const processJsonData = (jsonData, name) => {
    setData(jsonData);
    setFileName(name);
    const tags = new Set(jsonData.strings.flatMap((s) => s.tags));
    const defaultEnabled = new Set(tags);
    defaultEnabled.delete('#code');
    defaultEnabled.delete('#reloc');
    
    setAllTags(Array.from(tags).sort());
    setEnabledTags(defaultEnabled);
  };

  const handleFileUpload = (event) => {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const jsonData = JSON.parse(e.target.result);
        processJsonData(jsonData, file.name);
      } catch (error) {
        alert('Error parsing JSON file!');
        console.error(error);
      }
    };
    reader.readAsText(file);
  };

  const handleTagChange = (tag, isEnabled) => {
    const newEnabledTags = new Set(enabledTags);
    if (isEnabled) {
      newEnabledTags.add(tag);
    } else {
      newEnabledTags.delete(tag);
    }
    setEnabledTags(newEnabledTags);
  };

  const filteredStrings = data
    ? data.strings.filter((s) => {
        const searchMatch = s.string.toLowerCase().includes(searchTerm.toLowerCase());
        if (!searchMatch) return false;
        return s.tags.every((tag) => enabledTags.has(tag));
      })
    : [];

  return (
    <div className="App">
      <div className="controls">
        <div className="file-upload-area">
          <label htmlFor="file-upload" className="file-upload-label">
            {fileName ? `Loaded: ${fileName}` : 'Upload results.json'}
          </label>
          <input id="file-upload" type="file" accept=".json" onChange={handleFileUpload} />
        </div>
        {data && (
          <>
            <input
              type="text"
              placeholder="Search strings..."
              className="search-bar"
              onChange={(e) => setSearchTerm(e.target.value)}
            />
            <TagFilter tags={allTags} enabledTags={enabledTags} onTagChange={handleTagChange} />
          </>
        )}
      </div>
      <div className="results-container">
        {data ? (
          <Layout layout={data.layout} strings={filteredStrings} />
        ) : (
          <div className="welcome-message">Please upload a `results.json` file to begin.</div>
        )}
      </div>
    </div>
  );
}

export default App;