// Load theme and mode immediately to prevent flash of unstyled content.
// This file must be loaded synchronously in <head>.
(function() {
    var theme = localStorage.getItem('ion-theme') || 'cyan';
    var mode = localStorage.getItem('ion-mode') || 'dark';
    var glass = localStorage.getItem('ion-glass') || 'on';
    document.documentElement.setAttribute('data-theme', theme);
    document.documentElement.setAttribute('data-mode', mode);
    document.documentElement.setAttribute('data-glass', glass);
})();
