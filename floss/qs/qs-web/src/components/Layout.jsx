import React from 'react';
import StringView from './StringView';

/**
 * Recursively checks if a layout node or any of its children contain any of the provided strings.
 * This is used to determine if a layout section should be rendered at all.
 * @param {object} layout - The layout node to check.
 * @param {array} strings - The list of strings to check against.
 * @returns {boolean} - True if the layout or its descendants contain visible strings.
 */
function hasVisibleStrings(layout, strings) {
  const ownStringsVisible = strings.some(
    (s) => s.offset >= layout.offset && s.offset < layout.offset + layout.size
  );

  if (ownStringsVisible) {
    return true;
  }

  return layout.children.some((child) => hasVisibleStrings(child, strings));
}

const Layout = ({ layout, strings }) => {
  // If this layout and all its children have no visible strings after filtering,
  // don't render this component at all.
  if (!hasVisibleStrings(layout, strings)) {
    return null;
  }

  // Get the start and end offsets of all direct children.
  const childRanges = layout.children.map(child => ({
    start: child.offset,
    end: child.offset + child.size,
  }));

  // Filter for strings that are within the current layout's bounds but NOT within any of its children's bounds.
  // These are the strings that belong directly to this layout node.
  const layoutStrings = strings.filter(s => {
    const isInParent = s.offset >= layout.offset && s.offset < layout.offset + layout.size;
    if (!isInParent) {
      return false;
    }

    const isInAnyChild = childRanges.some(
      range => s.offset >= range.start && s.offset < range.end
    );

    return !isInAnyChild;
  });

  // Recursively render children, passing the full list of filtered strings down.
  // The child components will perform the same logic to find their own direct strings.
  const childComponents = layout.children.map((child) => (
    <Layout key={child.offset} layout={child} strings={strings} />
  ));

  // Only render this layout if it has direct strings or if any of its children will be rendered.
  if (layoutStrings.length === 0 && childComponents.every(c => c === null)) {
      return null;
  }

  return (
    <div className="layout">
      <div className="layout-header">{layout.name}</div>
      <div className="layout-content">
        {layoutStrings.map((s) => (
          <StringView key={s.offset} string={s} />
        ))}
        {childComponents}
      </div>
    </div>
  );
};

export default Layout;
