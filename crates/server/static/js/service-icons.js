/**
 * Service icon/logo helpers — shared across all pages.
 *
 * Logo mappings are defined in /data/service-logos.json (source of truth)
 * and served from /data/service-logos.json (embedded static asset).
 * This keeps the data separate from code and easy to extend.
 */

var SERVICE_LOGOS = {};
var SERVICE_HOST_MAP = {};
var SERVICE_DARK_INVERT = [];

// Load logo data synchronously before Alpine.js initializes.
// The JSON is a local embedded asset (<1KB), not an external request.
(function() {
    var req = new XMLHttpRequest();
    req.open('GET', '/data/service-logos.json', false);
    req.send();
    if (req.status === 200) {
        var data = JSON.parse(req.responseText);
        SERVICE_LOGOS = data.logos || {};
        SERVICE_HOST_MAP = data.host_map || {};
        SERVICE_DARK_INVERT = data.dark_mode_invert || [];
        // Resolve aliases to their logo URLs
        var aliases = data.aliases || {};
        for (var alias in aliases) {
            var target = aliases[alias];
            if (SERVICE_LOGOS[target]) {
                SERVICE_LOGOS[alias] = SERVICE_LOGOS[target];
            }
        }
    }
})();

/** Returns 'logo-dark-invert' if this logo key needs inversion in dark mode, else ''. */
function logoDarkClass(key) {
    if (!key) return '';
    return SERVICE_DARK_INVERT.indexOf(key.toLowerCase()) >= 0 ? 'logo-dark-invert' : '';
}

/** Get bundled logo URL for a service key (e.g., "github", "slack"). Returns null if unknown. */
function serviceLogoUrl(key) {
    if (!key) return null;
    return SERVICE_LOGOS[key.toLowerCase()] || null;
}

/** Resolve a credential object to a logo key using tags and service hostname. */
function credLogoKey(cred) {
    var svc = (cred.service || '').toLowerCase();
    var tags = cred.tags || [];
    for (var i = 0; i < tags.length; i++) {
        if (SERVICE_LOGOS[tags[i].toLowerCase()]) return tags[i].toLowerCase();
    }
    for (var host in SERVICE_HOST_MAP) {
        if (svc.indexOf(host) >= 0) return SERVICE_HOST_MAP[host];
    }
    if (SERVICE_LOGOS[svc]) return svc;
    return null;
}

/** Get logo URL for a credential. Returns null for unknown services (letter fallback). */
function credFaviconSrc(cred) {
    var key = credLogoKey(cred);
    if (key && SERVICE_LOGOS[key]) return SERVICE_LOGOS[key];
    return null;
}

/** Get initial letter for a credential's fallback avatar. */
function credFaviconInitial(cred) {
    return ((cred.name || cred.service || '?')[0] || '?').toUpperCase();
}

/** Get logo URL for a credential template. */
function credTplLogoUrl(tpl) {
    var key = (tpl.key || '').toLowerCase();
    if (SERVICE_LOGOS[key] !== undefined) return SERVICE_LOGOS[key];
    var tags = tpl.tags || [];
    for (var i = 0; i < tags.length; i++) {
        var t = tags[i].toLowerCase();
        if (SERVICE_LOGOS[t]) return SERVICE_LOGOS[t];
    }
    return null;
}
