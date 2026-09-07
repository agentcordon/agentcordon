/*
 * AgentCordon shared UI primitives — `window.AC`.
 *
 * The admin console grew by copy-and-paste. By v0.4.0 it carried four
 * confirmation patterns (a partial, a dozen inline modals, native `confirm()`,
 * native `alert()`), twenty-one hand-written copies of one error reporter, and
 * sixty-three mutating `fetch` calls of which nine never looked at the
 * response — so deleting an OIDC provider toasted "Provider deleted" on a 403,
 * and an expired session turned every button into a no-op.
 *
 * Everything a page does to the server or to the user's attention goes through
 * this file: one dialog, one fetch, one error reporter, one toast. It is plain
 * ES5-with-async, loaded synchronously in `<head>` so Alpine expressions can
 * call it during `x-init`.
 */
(function () {
    'use strict';

    var AC = window.AC || (window.AC = {});

    /* ===================================================================== */
    /* CSRF                                                                  */
    /* ===================================================================== */

    AC.csrfToken = function () {
        var match = document.cookie.match(/agtcrdn_csrf=([^;]+)/);
        return match ? match[1] : '';
    };

    /* ===================================================================== */
    /* Toasts                                                                */
    /* ===================================================================== */

    /*
     * A toast with nothing to say is worse than no toast: the review found two
     * empty black rectangles beside a real error on the MCP install modal,
     * because a failed response was reported by reading a field that was not
     * there. An empty message is a bug in the caller; swallow it rather than
     * render it, and let the caller's fallback do the talking.
     */
    AC.toast = function (message, type, options) {
        if (!message || !String(message).trim()) return false;
        var detail = { message: String(message), type: type || 'info' };
        if (options && options.duration) detail.duration = options.duration;
        window.dispatchEvent(new CustomEvent('toast', { detail: detail }));
        return true;
    };

    /* The name every template already calls. */
    window.showToast = AC.toast;

    /*
     * Report a failed response with the server's own sentence.
     *
     * A refusal the page could not predict — a policy deny, a row someone else
     * deleted, a 409 that names how many credentials still use an OAuth client
     * — used to fall out of an `if (resp.ok)` into nothing at all: the console
     * got a 403 and the operator got a button that looked like it had worked.
     * The server always says why in `error.message`; say it.
     */
    AC.reportError = async function (resp, fallback) {
        var message = '';
        try {
            var data = await resp.json();
            message = (data && data.error && data.error.message) || '';
        } catch (e) { /* a non-JSON body has nothing to quote */ }
        if (!message && typeof fallback === 'string') message = fallback;
        if (!message) {
            message = resp && resp.status
                ? 'Request failed (' + resp.status + ')'
                : 'Request failed.';
        }
        AC.toast(message, 'error');
        return message;
    };

    /* The old global name, kept so no call site has to change to be correct. */
    window.reportApiError = AC.reportError;

    /* ===================================================================== */
    /* fetch                                                                 */
    /* ===================================================================== */

    var MUTATING = { POST: true, PUT: true, PATCH: true, DELETE: true };
    var SESSION_EXPIRED = 'Your session expired. Please sign in again.';

    /*
     * `AC.fetch` is the only way a page talks to the API.
     *
     * It adds the CSRF header to every mutating method (so a call site cannot
     * forget it) and turns a 401 into the navigation the user is owed: before
     * this, an expired cookie made every in-page action silently do nothing,
     * and only a full page load reached the login screen.
     *
     * The returned promise never settles once a redirect has started, so a
     * caller's `if (!resp.ok) reportError(...)` cannot flash "Request failed
     * (401)" over a page that is already leaving.
     */
    AC.fetch = function (url, options) {
        var opts = Object.assign({}, options || {});
        var method = (opts.method || 'GET').toUpperCase();

        if (MUTATING[method]) {
            if (window.Headers && opts.headers instanceof Headers) {
                if (!opts.headers.has('X-CSRF-Token')) {
                    opts.headers.set('X-CSRF-Token', AC.csrfToken());
                }
            } else {
                var headers = Object.assign({}, opts.headers || {});
                var hasCsrf = Object.keys(headers).some(function (k) {
                    return k.toLowerCase() === 'x-csrf-token';
                });
                if (!hasCsrf) headers['X-CSRF-Token'] = AC.csrfToken();
                opts.headers = headers;
            }
        }

        var noRedirect = opts.onUnauthorized === 'ignore';
        delete opts.onUnauthorized;

        return fetch(url, opts).then(function (resp) {
            if (resp.status === 401 && !noRedirect && window.location.pathname !== '/login') {
                var next = window.location.pathname + window.location.search;
                window.location.href = '/login?next=' + encodeURIComponent(next) +
                    '&message=' + encodeURIComponent(SESSION_EXPIRED);
                return new Promise(function () { /* the page is navigating away */ });
            }
            return resp;
        });
    };

    /* ===================================================================== */
    /* Modal focus management                                                */
    /* ===================================================================== */

    var FOCUSABLE = [
        'a[href]', 'button:not([disabled])', 'input:not([disabled]):not([type="hidden"])',
        'select:not([disabled])', 'textarea:not([disabled])', '[tabindex]:not([tabindex="-1"])'
    ].join(',');

    function focusableIn(el) {
        return Array.prototype.filter.call(el.querySelectorAll(FOCUSABLE), function (node) {
            return node.offsetWidth > 0 || node.offsetHeight > 0 || node === document.activeElement;
        });
    }

    /* Everything the dialog is not becomes `inert`, so a screen reader's
     * virtual cursor and a pointer cannot reach the page behind the overlay —
     * Tab trapping alone leaves both of those routes open. */
    function makeRestOfPageInert(el) {
        var marked = [];
        Array.prototype.forEach.call(document.body.children, function (child) {
            if (child === el || child.contains(el)) return;
            /* An error raised by the dialog's own action lands in the toast
               region; making that inert would hide the reason the dialog
               failed from the reader it was written for. */
            if (child.classList && child.classList.contains('toast-container')) return;
            if (child.hasAttribute('inert')) return;
            child.setAttribute('inert', '');
            marked.push(child);
        });
        return function () {
            marked.forEach(function (child) { child.removeAttribute('inert'); });
        };
    }

    /*
     * `AC.modal(el, opts)` gives an already-rendered dialog the behaviour a
     * dialog owes a keyboard user: initial focus inside it, Tab and Shift+Tab
     * confined to it, the page behind inert, Escape to leave, and focus
     * restored to whatever opened it.
     *
     * Modals that carry a form (install, share, credential edit) keep their own
     * markup and call this; plain confirmations use `AC.confirm` instead.
     *
     * Returns a handle with `release()`.
     */
    AC.modal = function (el, opts) {
        if (!el) return { release: function () {} };
        opts = opts || {};

        var opener = document.activeElement;
        var undoInert = makeRestOfPageInert(el);

        function onKeydown(e) {
            if (e.key === 'Escape' && opts.onEscape) {
                opts.onEscape(e);
                return;
            }
            if (e.key !== 'Tab') return;
            var items = focusableIn(el);
            if (items.length === 0) {
                e.preventDefault();
                return;
            }
            var first = items[0];
            var last = items[items.length - 1];
            if (e.shiftKey && (document.activeElement === first || !el.contains(document.activeElement))) {
                e.preventDefault();
                last.focus();
            } else if (!e.shiftKey && (document.activeElement === last || !el.contains(document.activeElement))) {
                e.preventDefault();
                first.focus();
            }
        }

        document.addEventListener('keydown', onKeydown, true);

        /* Initial focus: whatever the caller nominated, else the first control
         * that is not the destructive one. */
        var initial = opts.initialFocus
            ? (typeof opts.initialFocus === 'string' ? el.querySelector(opts.initialFocus) : opts.initialFocus)
            : focusableIn(el)[0];
        if (initial) {
            try { initial.focus(); } catch (e) { /* detached */ }
        }

        var released = false;
        return {
            release: function () {
                if (released) return;
                released = true;
                document.removeEventListener('keydown', onKeydown, true);
                undoInert();
                /* restore focus to the control that opened the dialog */
                if (opener && document.contains(opener)) {
                    try { opener.focus(); } catch (e) { /* gone */ }
                }
            }
        };
    };

    /* ===================================================================== */
    /* AC.confirm / AC.prompt                                                */
    /* ===================================================================== */

    var CONFIRM_MARKUP =
        '<div class="modal" role="document">' +
        '<h3 id="ac-confirm-title"></h3>' +
        '<p id="ac-confirm-message"></p>' +
        '<div class="ac-confirm-field" id="ac-confirm-field" hidden>' +
        '<label class="form-label" for="ac-confirm-input" id="ac-confirm-input-label"></label>' +
        '<input class="form-input" type="text" id="ac-confirm-input">' +
        '</div>' +
        '<div class="modal-actions">' +
        '<button type="button" class="btn btn-secondary" id="ac-confirm-cancel">Cancel</button>' +
        '<button type="button" class="btn btn-primary" id="ac-confirm-ok">Confirm</button>' +
        '</div></div>';

    /* Pages that override `{% block body %}` (login, activate, consent, the
     * error shells) do not render the dialog server-side; build it on demand so
     * `AC.confirm` is available on every page, not most of them. */
    function confirmRoot() {
        var el = document.getElementById('ac-confirm');
        if (el) return el;
        el = document.createElement('div');
        el.id = 'ac-confirm';
        el.className = 'modal-overlay';
        el.setAttribute('role', 'dialog');
        el.setAttribute('aria-modal', 'true');
        el.setAttribute('aria-labelledby', 'ac-confirm-title');
        el.setAttribute('aria-describedby', 'ac-confirm-message');
        el.hidden = true;
        el.innerHTML = CONFIRM_MARKUP;
        document.body.appendChild(el);
        return el;
    }

    var openDialog = null;

    function runDialog(opts, wantsValue) {
        /* Two dialogs at once would fight over `inert` and over focus restore. */
        if (openDialog) openDialog(wantsValue ? null : false);

        var root = confirmRoot();
        var titleEl = root.querySelector('#ac-confirm-title');
        var msgEl = root.querySelector('#ac-confirm-message');
        var fieldEl = root.querySelector('#ac-confirm-field');
        var inputEl = root.querySelector('#ac-confirm-input');
        var labelEl = root.querySelector('#ac-confirm-input-label');
        var cancelEl = root.querySelector('#ac-confirm-cancel');
        var okEl = root.querySelector('#ac-confirm-ok');

        titleEl.textContent = opts.title || 'Are you sure?';
        msgEl.textContent = opts.message || '';
        msgEl.hidden = !opts.message;
        cancelEl.textContent = opts.cancelLabel || 'Cancel';
        okEl.textContent = opts.confirmLabel || (wantsValue ? 'Save' : 'Confirm');
        okEl.className = 'btn ' + (opts.danger ? 'btn-danger' : 'btn-primary');

        fieldEl.hidden = !wantsValue;
        if (wantsValue) {
            labelEl.textContent = opts.label || opts.title || '';
            inputEl.value = opts.initial || '';
        }

        root.hidden = false;

        return new Promise(function (resolve) {
            var handle;

            function settle(result) {
                if (!openDialog) return;
                openDialog = null;
                root.hidden = true;
                // Leave the hidden dialog neutral: a stale "Disable" label on a
                // hidden button is still a button named Disable to a DOM query.
                titleEl.textContent = '';
                msgEl.textContent = '';
                cancelEl.textContent = 'Cancel';
                okEl.textContent = 'Confirm';
                okEl.className = 'btn btn-primary';
                inputEl.value = '';
                cancelEl.removeEventListener('click', onCancel);
                okEl.removeEventListener('click', onOk);
                root.removeEventListener('mousedown', onBackdrop);
                if (handle) handle.release();
                resolve(result);
            }

            function onCancel() { settle(wantsValue ? null : false); }
            function onOk() { settle(wantsValue ? inputEl.value : true); }
            /* Clicking the backdrop is a cancel; clicking inside the card is not. */
            function onBackdrop(e) { if (e.target === root) settle(wantsValue ? null : false); }

            openDialog = settle;
            cancelEl.addEventListener('click', onCancel);
            okEl.addEventListener('click', onOk);
            root.addEventListener('mousedown', onBackdrop);

            handle = AC.modal(root, {
                /* Initial focus lands on Cancel, never on the destructive
                 * button: the review found Delete focused on open, one Enter
                 * away from a deletion the reader had not finished reading. */
                initialFocus: wantsValue ? inputEl : cancelEl,
                onEscape: function () { settle(wantsValue ? null : false); }
            });

            if (wantsValue) {
                inputEl.onkeydown = function (e) {
                    if (e.key === 'Enter') { e.preventDefault(); onOk(); }
                };
            }
        });
    }

    /*
     * `AC.confirm({title, message, confirmLabel, cancelLabel, danger})`
     * → Promise<boolean>. The one confirmation in the product.
     */
    AC.confirm = function (opts) {
        return runDialog(opts || {}, false);
    };

    /* `AC.prompt({title, label, initial, confirmLabel})` → Promise<string|null>,
     * replacing the one native `prompt()` (saving a tester scenario). */
    AC.prompt = function (opts) {
        return runDialog(opts || {}, true);
    };

    /* ===================================================================== */
    /* Every overlay is a dialog, whoever wrote it                           */
    /* ===================================================================== */

    /*
     * Sixteen `.modal-overlay` blocks were written by hand across eleven files
     * and not one of them managed focus: Tab from an open Delete modal walked
     * the page behind it, and a screen reader never learned the page was
     * covered. The ones that carry a form (install, share, re-seal, restore)
     * keep their own markup and their own open flag — what they were missing is
     * the behaviour, and the behaviour does not need to know their names.
     *
     * So every overlay gets it, from here, when it becomes visible.
     * `#ac-confirm` is excluded: `runDialog` already holds its handle.
     */
    function isVisible(el) {
        return !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
    }

    function scanOverlays() {
        var overlays = document.querySelectorAll('.modal-overlay');
        Array.prototype.forEach.call(overlays, function (el) {
            if (el.id === 'ac-confirm') return;
            var visible = isVisible(el);
            if (visible && !el.__acModal) {
                el.__acModal = AC.modal(el, {
                    /* The destructive button is usually last in the markup and
                       Cancel first, so "first focusable" is already the safe
                       one; a form modal focuses its first field. */
                    initialFocus: el.querySelector('input:not([type="hidden"]), select, textarea') || undefined
                });
            } else if (!visible && el.__acModal) {
                el.__acModal.release();
                el.__acModal = null;
            }
        });
    }

    AC.scanOverlays = scanOverlays;

    /* ===================================================================== */
    /* Tables scroll instead of clipping                                     */
    /* ===================================================================== */

    /*
     * On a 390 px viewport every `.tbl` collapsed to one- and two-character
     * columns: a `display:block` table shrink-wraps its anonymous table box
     * instead of overflowing it, so `overflow-x` had nothing to scroll. The fix
     * is a wrapper, and there are forty-odd tables across the templates and the
     * AJAX partials — so the wrapper is added here, once, including for markup
     * that arrives later from a detail-pane fetch.
     */
    function wrapTables(root) {
        var tables = (root || document).querySelectorAll('table.tbl');
        Array.prototype.forEach.call(tables, function (table) {
            var parent = table.parentNode;
            if (!parent || (parent.classList && parent.classList.contains('tbl-scroll'))) return;
            var wrap = document.createElement('div');
            wrap.className = 'tbl-scroll';
            parent.insertBefore(wrap, table);
            wrap.appendChild(table);
        });
    }


    /* Whole-row links. A clickable row carries one real anchor (`a.row-link`)
       in its name cell; the CSS stretches that anchor's ::after over the row
       where the row is its containing block. Chromium does not treat a
       positioned <tr> as a containing block (a long-standing gap Firefox does
       not share), so a click on any other cell would land on nothing. This
       delegate forwards such a click to the row's anchor as a synthetic click
       carrying the same modifier keys, so the navigation is still the
       anchor's own: middle-click and ctrl-click open a new tab as usual, and
       a click on a control inside the row (a button, a link, a form field)
       is left alone. */
    function rowLinkDelegate(e) {
        if (e.defaultPrevented || e.button > 1) return;
        var target = e.target;
        if (!(target instanceof Element)) return;
        if (target.closest('a, button, input, select, textarea, label, summary, [role="button"], [role="menuitem"]')) return;
        var row = target.closest('.tbl-clickable tbody tr');
        if (!row) return;
        var anchor = row.querySelector('a.row-link');
        if (!anchor) return;
        var synthetic = new MouseEvent('click', {
            bubbles: true, cancelable: true, view: window, button: e.button,
            ctrlKey: e.ctrlKey, metaKey: e.metaKey, shiftKey: e.shiftKey, altKey: e.altKey
        });
        anchor.dispatchEvent(synthetic);
    }
    document.addEventListener('click', rowLinkDelegate);
    document.addEventListener('auxclick', rowLinkDelegate);
    AC.rowLinkDelegate = rowLinkDelegate;
    AC.wrapTables = wrapTables;

    function sweep() {
        wrapTables(document);
        scanOverlays();
    }

    function watchDom() {
        sweep();
        if (!window.MutationObserver) return;
        var pending = false;
        var observer = new MutationObserver(function () {
            if (pending) return;
            pending = true;
            /* Alpine toggles `style="display:none"` and the detail panes insert
               whole subtrees; coalesce into one pass per frame. */
            window.requestAnimationFrame(function () {
                pending = false;
                sweep();
            });
        });
        observer.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ['style', 'class', 'hidden']
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', watchDom);
    } else {
        watchDom();
    }
})();
