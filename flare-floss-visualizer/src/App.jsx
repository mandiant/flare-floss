import React, { useState, useEffect } from 'react';
import Layout from './components/Layout';
import TagFilter from './components/TagFilter';
import './App.css';

function App() {
  const [data, setData] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [enabledTags, setEnabledTags] = useState(new Set());
  const [allTags, setAllTags] = useState([]);

  useEffect(() => {
    fetch('/results.json')
      .then((response) => response.json())
      .then((data) => {
        setData(data);
        const tags = new Set(data.strings.flatMap((s) => s.tags));
        const defaultEnabled = new Set(tags);
        defaultEnabled.delete('#code');
        defaultEnabled.delete('#reloc');
        
        setAllTags(Array.from(tags).sort());
        setEnabledTags(defaultEnabled);
      });
  }, []);

  const handleTagChange = (tag, isEnabled) => {
    const newEnabledTags = new Set(enabledTags);
    if (isEnabled) {
      newEnabledTags.add(tag);
    } else {
      newEnabledTags.delete(tag);
    }
    setEnabledTags(newEnabledTags);
  };

  if (!data) {
    return <div>Loading...</div>;
  }

  const filteredStrings = data.strings.filter((s) => {
    // Filter by search term first
    const searchMatch = s.string.toLowerCase().includes(searchTerm.toLowerCase());
    if (!searchMatch) {
      return false;
    }

    // Then, filter by tags. A string is only visible if ALL of its tags are enabled.
    // An untagged string will always pass this check.
    return s.tags.every((tag) => enabledTags.has(tag));
  });

  return (
    <div className="App">
      <div className="controls">
        <input
          type="text"
          placeholder="Search strings..."
          className="search-bar"
          onChange={(e) => setSearchTerm(e.target.value)}
        />
        <TagFilter tags={allTags} enabledTags={enabledTags} onTagChange={handleTagChange} />
      </div>
      <div className="results-container">
        <Layout layout={data.layout} strings={filteredStrings} />
      </div>
    </div>
  );
}

export default App;
