(function () {
  var KEY = 'sub-hub.console.v1';
  var LIGHT = '#fafafa';
  var DARK = '#0a0a0a';
  var theme = 'system';
  var locale;
  try {
    var raw = localStorage.getItem(KEY);
    if (raw) {
      var parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        if (parsed.theme === 'light' || parsed.theme === 'dark' || parsed.theme === 'system') {
          theme = parsed.theme;
        }
        if (parsed.locale === 'zh' || parsed.locale === 'en') {
          locale = parsed.locale;
        }
      }
    }
  } catch {
    theme = 'system';
    locale = undefined;
  }

  var prefersDark = false;
  try {
    prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  } catch {
    prefersDark = false;
  }

  var resolved = theme === 'light' || theme === 'dark' ? theme : prefersDark ? 'dark' : 'light';
  var root = document.documentElement;
  root.classList.remove('light', 'dark');
  root.classList.add(resolved);

  var language = '';
  try {
    language = String(navigator.language || '');
  } catch {
    language = '';
  }
  if (locale === 'zh') {
    root.lang = 'zh-CN';
  } else if (locale === 'en') {
    root.lang = 'en';
  } else {
    root.lang = language.toLowerCase().indexOf('zh') === 0 ? 'zh-CN' : 'en';
  }

  var existing = document.querySelectorAll('meta[name="theme-color"]');
  for (var i = 0; i < existing.length; i++) {
    var node = existing[i];
    if (node.parentNode) {
      node.parentNode.removeChild(node);
    }
  }

  function addThemeColor(content, media) {
    var meta = document.createElement('meta');
    meta.setAttribute('name', 'theme-color');
    meta.setAttribute('content', content);
    if (media) {
      meta.setAttribute('media', media);
    }
    document.head.appendChild(meta);
  }

  if (theme === 'light') {
    addThemeColor(LIGHT);
  } else if (theme === 'dark') {
    addThemeColor(DARK);
  } else {
    addThemeColor(LIGHT, '(prefers-color-scheme: light)');
    addThemeColor(DARK, '(prefers-color-scheme: dark)');
  }
})();
