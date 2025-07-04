import React from 'react';

const TagFilter = ({ tags, enabledTags, onTagChange }) => {
  return (
    <div className="tag-filter">
      {tags.map((tag) => (
        <label key={tag}>
          <input
            type="checkbox"
            checked={enabledTags.has(tag)}
            onChange={(e) => onTagChange(tag, e.target.checked)}
          />
          {tag}
        </label>
      ))}
    </div>
  );
};

export default TagFilter;
