import React from 'react';

const StringView = ({ string }) => {
  const getTagStyle = (tag) => {
    if (tag.startsWith('#winapi')) {
      return { color: 'cyan' };
    }
    if (tag.startsWith('#common')) {
      return { color: 'gray' };
    }
    if (tag.startsWith('#code')) {
      return { color: 'red' };
    }
    return {};
  };

  return (
    <div className="string-view">
      <span className="offset">0x{string.offset.toString(16).padStart(8, '0')}</span>
      <span className="string">{string.string}</span>
      <span className="tags">
        {string.tags.map((tag) => (
          <span key={tag} className="tag" style={getTagStyle(tag)}>
            {tag}
          </span>
        ))}
      </span>
    </div>
  );
};

export default StringView;
