// Run before styles to avoid flashing the wrong theme. Storage may be disabled.
(function () {
  'use strict';
  var root = document.documentElement;
  function get(key, fallback) { try { return localStorage.getItem(key) || fallback; } catch (_) { return fallback; } }
  function save(key, value) { try { localStorage.setItem(key, value); } catch (_) {} }
  var theme = get('proxy-manager-theme', window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  var lang = get('proxy-manager-language', 'en');
  function applyTheme(value) {
    theme = value === 'light' ? 'light' : 'dark'; root.dataset.theme = theme;
    var button = document.getElementById('theme-toggle');
    if (button) { button.textContent = theme === 'dark' ? 'Light mode' : 'Dark mode'; button.setAttribute('aria-pressed', String(theme === 'light')); }
  }
  function applyLanguage(value) {
    lang = value === 'fa' ? 'fa' : 'en'; root.lang = lang; root.dir = lang === 'fa' ? 'rtl' : 'ltr';
    var button = document.getElementById('language-toggle');
    if (button) { button.textContent = lang === 'fa' ? 'English' : 'فارسی'; }
  }
  applyTheme(theme); applyLanguage(lang);
  document.addEventListener('DOMContentLoaded', function () {
    applyTheme(theme); applyLanguage(lang);
    var themeButton = document.getElementById('theme-toggle'), languageButton = document.getElementById('language-toggle');
    if (themeButton) themeButton.addEventListener('click', function () { applyTheme(theme === 'dark' ? 'light' : 'dark'); save('proxy-manager-theme', theme); if (window.I18n) window.I18n.refresh(); });
    if (languageButton) languageButton.addEventListener('click', function () { applyLanguage(lang === 'en' ? 'fa' : 'en'); save('proxy-manager-language', lang); if (window.I18n) window.I18n.refresh(); });
  });
}());
