/* CyAB systems list: select-all and the bulk bar's count.
 *
 * Listeners sit on document, so they keep working after htmx swaps
 * #cyab-main. ES5, like the rest of static/js.
 */
(function () {
    "use strict";

    function refresh(form) {
        var boxes = form.querySelectorAll('input[name="ids"]');
        var n = 0;
        for (var i = 0; i < boxes.length; i++) {
            if (boxes[i].checked) { n++; }
        }
        var label = form.querySelector("[data-cyab-selected]");
        if (label) { label.textContent = n + " selected"; }
        var buttons = form.querySelectorAll("[data-cyab-needs-selection]");
        for (var j = 0; j < buttons.length; j++) { buttons[j].disabled = n === 0; }
        var all = form.querySelector("[data-cyab-select-all]");
        if (all) {
            all.checked = n > 0 && n === boxes.length;
            all.indeterminate = n > 0 && n < boxes.length;
        }
    }

    document.addEventListener("change", function (event) {
        var target = event.target;
        var form = target.closest && target.closest("[data-cyab-bulk]");
        if (!form) { return; }
        if (target.hasAttribute("data-cyab-select-all")) {
            var boxes = form.querySelectorAll('input[name="ids"]');
            for (var i = 0; i < boxes.length; i++) { boxes[i].checked = target.checked; }
        }
        refresh(form);
    });
})();
