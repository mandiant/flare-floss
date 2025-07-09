import React from 'react';

const StringView = ({ string }) => {
  const getTagStyle = (tag) => {
    if (tag.startsWith('#winapi')) return { color: '#4ec9b0' };
    if (tag.startsWith('#common')) return { color: '#808080' };
    if (tag.startsWith('#code')) return { color: '#ce9178' };
    return {};
  };

  return (
    <div className="string-view">
      <span className="string-content">{string.string}</span>
      <span className="string-tags">
        {string.tags.map(tag => (
          <span key={tag} style={getTagStyle(tag)}>{tag} </span>
        ))}
      </span>
      <span className="string-offset">{string.offset.toString(16).padStart(8, '0')}</span>
      <span className="string-structure">
        {string.structure ? `/${string.structure}` : ''}
      </span>
    </div>
  );
};

export default StringView;
