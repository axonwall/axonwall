(function () {
  try {
    var tid = localStorage.getItem('axonwall_theme_id') || 'axonwall-emerald';
    if (!/^[a-z0-9_-]{1,64}$/.test(tid)) {
      tid = 'axonwall-emerald';
    }
    document.documentElement.setAttribute('data-theme', tid);
  } catch (e) {}
})();
