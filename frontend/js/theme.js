/* 라이트(Flatly)/다크(Darkly) 테마 — 화면 깜박임을 막기 위해 <head> 에서 동기 실행 */
(function () {
  var saved = null;
  try { saved = localStorage.getItem('cp-theme'); } catch (e) {}
  var dark = saved ? saved === 'dark' : window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  window.cpSetTheme = function (isDark, persist) {
    document.documentElement.setAttribute('data-bs-theme', isDark ? 'dark' : 'light');
    var l = document.getElementById('css-light'), d = document.getElementById('css-dark');
    if (l) l.media = isDark ? 'not all' : 'all';
    if (d) d.media = isDark ? 'all' : 'not all';
    if (persist) { try { localStorage.setItem('cp-theme', isDark ? 'dark' : 'light'); } catch (e) {} }
  };
  window.cpIsDark = function () { return document.documentElement.getAttribute('data-bs-theme') === 'dark'; };
  window.cpSetTheme(dark, false); // 두 <link> 가 이미 파싱된 뒤 실행되므로 즉시 적용
})();
