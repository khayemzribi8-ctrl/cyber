"""Inline SVG icon set (offline, no icon font/CDN). 1.6px stroke, 24x24 grid."""

_P = ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"'
      ' stroke-linecap="round" stroke-linejoin="round">{}</svg>')

_PATHS = {
    "grid": '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
    "shield": '<path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z"/>',
    "server": '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><circle cx="7" cy="7.5" r="0.6" fill="currentColor"/><circle cx="7" cy="16.5" r="0.6" fill="currentColor"/>',
    "sitemap": '<rect x="9" y="3" width="6" height="4" rx="1"/><rect x="3" y="17" width="6" height="4" rx="1"/><rect x="15" y="17" width="6" height="4" rx="1"/><path d="M12 7v4M6 17v-2h12v2M12 11v4"/>',
    "id": '<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2.2"/><path d="M14 10h4M14 13h3M6 16c.7-1.6 4.3-1.6 5 0"/>',
    "directory": '<path d="M4 6a8 3 0 0 0 16 0M4 6a8 3 0 0 1 16 0v12a8 3 0 0 1-16 0zM4 12a8 3 0 0 0 16 0"/>',
    "ticket": '<path d="M4 8a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2 2 2 0 0 0 0 4 2 2 0 0 1 0 4H6a2 2 0 0 1-2-2 2 2 0 0 0 0-4z"/><path d="M12 6v2M12 11v2M12 16v2"/>',
    "share": '<circle cx="6" cy="12" r="2.4"/><circle cx="18" cy="6" r="2.4"/><circle cx="18" cy="18" r="2.4"/><path d="M8.1 11l7.8-4M8.1 13l7.8 4"/>',
    "windows": '<path d="M3 5l8-1v7H3zM11 4l10-1v9H11zM3 12h8v7l-8-1zM11 12h10v9l-10-1z"/>',
    "desktop": '<rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M8 20h8M12 16v4"/>',
    "terminal": '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/>',
    "certificate": '<circle cx="12" cy="9" r="5"/><path d="M9 13l-1 7 4-2 4 2-1-7"/><path d="M12 6v3l2 1"/>',
    "linux": '<path d="M9 4c-1 2 0 4 0 5-1 2-3 4-3 7 0 2 2 3 6 3s6-1 6-3c0-3-2-5-3-7 0-1 1-3 0-5-1-2-5-2-6 0z"/><circle cx="10" cy="9" r="0.6" fill="currentColor"/><circle cx="14" cy="9" r="0.6" fill="currentColor"/>',
    "network": '<circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v4M12 11l-5.5 6M12 11l5.5 6"/>',
    "bug": '<rect x="8" y="8" width="8" height="10" rx="4"/><path d="M12 8V5M9 5l-1-2M15 5l1-2M8 11H4M20 11h-4M8 15H4M20 15h-4"/>',
    "target": '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="4"/><circle cx="12" cy="12" r="0.8" fill="currentColor"/>',
    "route": '<circle cx="6" cy="18" r="2"/><circle cx="18" cy="6" r="2"/><path d="M8 18h6a3 3 0 0 0 0-6H9a3 3 0 0 1 0-6h3"/>',
    "matrix": '<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 3v18M15 3v18M3 9h18M3 15h18"/>',
    "flag": '<path d="M5 21V4M5 4h11l-2 3 2 3H5"/>',
    "document": '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4M9 12h6M9 16h6"/>',
    "wrench": '<path d="M14 6a4 4 0 0 0-5 5l-5 5 2 2 5-5a4 4 0 0 0 5-5l-2 2-2-2z"/>',
    "check": '<path d="M4 12l5 5L20 6"/>',
    "report": '<rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 9v7M12 7v9M16 12v4"/>',
    "history": '<path d="M4 12a8 8 0 1 1 3 6"/><path d="M4 18v-4h4"/><path d="M12 8v4l3 2"/>',
    "gear": '<circle cx="12" cy="12" r="3"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3M6 6l2 2M16 16l2 2M18 6l-2 2M8 16l-2 2"/>',
    "cloud": '<path d="M7 18a4 4 0 0 1 .8-7.9A5 5 0 0 1 17 9a3.5 3.5 0 0 1 .5 7z"/>',
    "settings": '<circle cx="12" cy="12" r="3"/><path d="M19.4 13a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-2.7 1.1V21a2 2 0 0 1-4 0v-.2A1.6 1.6 0 0 0 7 19.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1A1.6 1.6 0 0 0 3 13H3a2 2 0 0 1 0-4h.2A1.6 1.6 0 0 0 4.7 7L4.6 7a2 2 0 1 1 2.8-2.8l.1.1A1.6 1.6 0 0 0 10 3.6V3a2 2 0 0 1 4 0v.2A1.6 1.6 0 0 0 17 4.7l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.4 1.7v0"/>',
    "logout": '<path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3M10 12h9M16 8l3 4-3 4"/>',
    "menu": '<path d="M4 6h16M4 12h16M4 18h16"/>',
    "search": '<circle cx="11" cy="11" r="6"/><path d="M20 20l-3.5-3.5"/>',
    "play": '<path d="M7 5l12 7-12 7z"/>',
    "copy": '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M4 16V5a1 1 0 0 1 1-1h11"/>',
    "download": '<path d="M12 4v11M8 11l4 4 4-4M5 20h14"/>',
    "alert": '<path d="M12 3l9 16H3z"/><path d="M12 9v5M12 17v.5"/>',
    "user": '<circle cx="12" cy="8" r="3.5"/><path d="M5 20a7 7 0 0 1 14 0"/>',
    "key": '<circle cx="8" cy="12" r="4"/><path d="M12 12h9M18 12v4M15 12v3"/>',
    "clock": '<circle cx="12" cy="12" r="8"/><path d="M12 8v4l3 2"/>',
}


def icon(name: str, cls: str = "") -> str:
    body = _PATHS.get(name, _PATHS["grid"])
    svg = _P.format(body)
    if cls:
        svg = svg.replace("<svg ", f'<svg class="{cls}" ', 1)
    return svg
