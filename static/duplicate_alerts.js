(() => {
    'use strict';
    const config = window.DUPLICATE_ALERT_CONFIG;
    if (!config) return;
    const dialog = document.getElementById('duplicate-validation-dialog');
    const content = document.getElementById('duplicate-dialog-content');
    const continueButton = document.getElementById('duplicate-dialog-continue');
    const approved = new WeakSet();
    const checking = new WeakSet();
    let pendingForm = null;
    let pendingSubmitter = null;

    function text(parent, tag, value, className) {
        const element = document.createElement(tag);
        element.textContent = value;
        if (className) element.className = className;
        parent.append(element);
        return element;
    }
    function dossierCard(parent, dossier) {
        const card = text(parent, 'div', '', 'duplicate-dossier');
        text(card, 'strong', `Dossier n°${dossier.id} — ${dossier.name}`);
        text(card, 'p', `Commercial responsable : ${dossier.owner_name}`);
        text(card, 'p', `SIRET : ${dossier.siret || '—'} · Statut : ${dossier.status || 'en_cours'}`);
        text(card, 'p', `Correspondances : ${dossier.reasons.join(' ; ')}`);
        if (dossier.url) {
            const link = text(card, 'a', 'Ouvrir le dossier');
            link.href = dossier.url;
            link.target = '_blank';
            link.rel = 'noopener';
        }
    }
    function closeDialog() {
        dialog.close();
        pendingForm = null;
        pendingSubmitter = null;
    }
    document.getElementById('duplicate-dialog-close').addEventListener('click', closeDialog);
    dialog.addEventListener('cancel', () => { pendingForm = null; pendingSubmitter = null; });
    continueButton.addEventListener('click', () => {
        const form = pendingForm;
        const submitter = pendingSubmitter;
        closeDialog();
        if (form) {
            approved.add(form);
            form.requestSubmit(submitter || undefined);
        }
    });
    function formContext(form) {
        if (form.method.toLowerCase() !== 'post') return null;
        const path = new URL(form.action, location.href).pathname;
        if (path === '/clients/create') return {kind: 'create'};
        const match = path.match(/^\/clients\/(\d+)\/(edit|status|cotation|cotations\/\d+\/edit)$/);
        if (!match) return null;
        return {clientId: match[1], kind: match[2] === 'edit' ? 'edit' : match[2] === 'status' ? 'status' : 'cotation'};
    }
    document.addEventListener('submit', async event => {
        const form = event.target;
        if (!(form instanceof HTMLFormElement)) return;
        const context = formContext(form);
        if (!context) return;
        if (approved.has(form)) { approved.delete(form); return; }
        event.preventDefault();
        event.stopImmediatePropagation();
        if (checking.has(form)) return;
        checking.add(form);
        const submitter = event.submitter;
        const data = new FormData(form);
        // This endpoint needs only text fields, never uploaded documents.
        for (const [key, value] of Array.from(data.entries())) {
            if (value instanceof File) data.delete(key);
        }
        data.set('duplicate_kind', context.kind);
        if (context.clientId) data.set('duplicate_client_id', context.clientId);
        try {
            const response = await fetch(config.checkUrl, {
                method: 'POST', body: data, credentials: 'same-origin',
                headers: {'X-CSRF-Token': config.csrfToken}, signal: AbortSignal.timeout(15000)
            });
            if (!response.ok || response.redirected) throw new Error('Check unavailable');
            const result = await response.json();
            if (!result.blocked && !result.dossiers.length) {
                approved.add(form);
                form.requestSubmit(submitter || undefined);
                return;
            }
            pendingForm = result.blocked ? null : form;
            pendingSubmitter = submitter;
            content.replaceChildren();
            continueButton.hidden = result.blocked;
            if (result.blocked) {
                text(content, 'p', "dossier bloqué, voir avec l'administrateur", 'duplicate-blocked-message');
            } else {
                text(content, 'p', 'Un dossier possède déjà les références saisies.');
                result.dossiers.forEach(dossier => dossierCard(content, dossier));
            }
            if (!dialog.open) dialog.showModal();
        } catch (error) {
            // The server still enforces duplicate blocking if the pre-check fails.
            approved.add(form);
            form.requestSubmit(submitter || undefined);
        } finally {
            checking.delete(form);
        }
    }, true);

    if (!config.feedUrl) return;
    const container = document.getElementById('duplicate-live-alerts');
    const badge = document.getElementById('duplicate-alert-count');
    const nav = document.getElementById('duplicate-alert-nav');
    const storageKey = `crm-duplicate-alert-cursor-${config.userId}`;
    let cursor = 0;
    try { cursor = Number(sessionStorage.getItem(storageKey)) || 0; } catch (_) { /* optional storage */ }
    let busy = false;
    async function poll() {
        if (busy || document.hidden) return;
        busy = true;
        try {
            const response = await fetch(`${config.feedUrl}?after=${cursor}`, {
                credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(10000)
            });
            if (!response.ok || response.redirected) return;
            const result = await response.json();
            badge.textContent = result.unread;
            badge.hidden = !result.unread;
            nav.classList.toggle('has-duplicate-alerts', result.unread > 0);
            for (const alert of result.alerts) {
                const card = text(container, 'section', '', 'duplicate-live-card');
                const dismiss = text(card, 'button', '×', 'btn btn-sm btn-outline-secondary');
                dismiss.type = 'button';
                dismiss.setAttribute('aria-label', 'Masquer cette notification');
                dismiss.addEventListener('click', () => card.remove());
                text(card, 'h3', '⚠ Doublon détecté');
                text(card, 'p', `Tentative par ${alert.actor_name} — ${alert.attempted_name || 'Dossier'}`);
                alert.dossiers.forEach(dossier => dossierCard(card, dossier));
                const link = text(card, 'a', 'Voir l’alerte complète');
                link.href = alert.url;
                // Keep a bounded notification stack; all attempts remain in history.
                while (container.children.length > 5) container.firstElementChild.remove();
            }
            cursor = result.cursor;
            try { sessionStorage.setItem(storageKey, String(cursor)); } catch (_) { /* optional storage */ }
        } catch (_) { /* retry automatically on the next poll */ }
        finally { busy = false; }
    }
    poll();
    setInterval(poll, 5000);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) poll(); });
})();
