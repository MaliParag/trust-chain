// Inserts the preview notice + Platform Trust Chain Series volume switcher at
// the top of every page's content across Windows, Apple, Linux, and Android.
(function () {
  function resolveSiteRoot() {
    var relToBook = (typeof path_to_root === 'string') ? path_to_root : '';
    var p = window.location.pathname || '';
    var subMounts = ['apple', 'linux', 'android'];
    for (var i = 0; i < subMounts.length; i++) {
      var seg = '/' + subMounts[i] + '/';
      if (p.indexOf(seg) !== -1) {
        return { root: relToBook + '../', active: subMounts[i] };
      }
    }
    return { root: relToBook, active: 'windows' };
  }

  function addBanner() {
    var main = document.querySelector('main');
    if (!main || document.getElementById('preview-banner')) return;

    var ctx = resolveSiteRoot();
    var r = ctx.root;
    var vols = [
      { slug: 'windows', label: 'Vol. I · Windows', href: r + 'index.html' },
      { slug: 'apple',   label: 'Vol. II · Apple',  href: r + 'apple/index.html' },
      { slug: 'linux',   label: 'Vol. III · Linux', href: r + 'linux/index.html' },
      { slug: 'android', label: 'Vol. IV · Android', href: r + 'android/index.html' }
    ];

    var pills = vols.map(function (v) {
      var cls = 'vol-pill' + (v.slug === ctx.active ? ' active' : '');
      return '<a class="' + cls + '" href="' + v.href + '">' + v.label + '</a>';
    }).join(' ');

    var banner = document.createElement('div');
    banner.id = 'preview-banner';
    banner.setAttribute('role', 'note');
    banner.innerHTML =
      '<div><strong>Preview edition.</strong> Open technical security monograph; ' +
      'corrections and reproductions welcome via ' +
      '<a href="https://github.com/MaliParag/windows-trust-chain/issues">GitHub Issues</a>.</div>' +
      '<div class="series-switcher"><span><strong>Platform Trust Chains:</strong></span> ' +
      pills +
      ' · <a href="' + r + 'series/index.html">Series Overview</a></div>';

    main.insertBefore(banner, main.firstChild);

    if (typeof path_to_root === 'string' && path_to_root === '') {
      var links = main.querySelectorAll('a[href^="../"]');
      for (var j = 0; j < links.length; j++) {
        var h = links[j].getAttribute('href');
        if (/^\.\.\/(front-matter|chapters|back-matter)\//.test(h)) {
          links[j].setAttribute('href', h.slice(3));
        }
      }
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', addBanner);
  } else {
    addBanner();
  }
})();
