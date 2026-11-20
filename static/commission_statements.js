(() => {
    const picker = document.getElementById('commercial-picker');
    if (!picker) return;
    const boxes = [...picker.querySelectorAll('input[name="commercial"]')];
    const update = () => {
        const count = boxes.filter(box => box.checked).length;
        document.getElementById('commercial-count').textContent = `Commerciaux : ${count || 'tous'}`;
    };
    picker.querySelectorAll('[data-select-commercials]').forEach(button => {
        button.addEventListener('click', () => {
            boxes.forEach(box => { box.checked = button.dataset.selectCommercials === 'all'; });
            update();
        });
    });
    boxes.forEach(box => box.addEventListener('change', update));
})();

(() => {
    const summary = document.getElementById('statement-live-summary');
    if (!summary) return;
    const status = document.getElementById('statement-live-status');
    const button = document.getElementById('statement-refresh');
    const money = new Intl.NumberFormat('fr-FR', { style: 'currency', currency: 'EUR' });
    let loading = false;
    async function refresh() {
        if (loading || document.hidden) return;
        loading = true;
        button.disabled = true;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000);
        try {
            const response = await fetch(summary.dataset.summaryUrl, {
                credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
                headers: { Accept: 'application/json' }
            });
            if (!response.ok || !response.headers.get('content-type')?.includes('application/json')) throw new Error('Unavailable');
            const data = await response.json();
            const fields = ['gross_total', 'net_total', 'total', 'paid', 'outstanding', 'period_rows',
                'missing_signature', 'pending', 'incomplete', 'missing_gross_count'];
            if (fields.some(key => data[key] == null || !Number.isFinite(Number(data[key])))) throw new Error('Invalid summary');
            document.querySelectorAll('[data-live-money]').forEach(node => {
                node.textContent = money.format(Number(data[node.dataset.liveMoney]));
            });
            document.querySelectorAll('[data-live-count]').forEach(node => {
                node.textContent = data[node.dataset.liveCount];
            });
            document.querySelectorAll('[data-warning]').forEach(node => {
                node.hidden = !data[node.dataset.warning];
            });
            document.getElementById('statement-data-warning').hidden = !(data.missing_signature || data.pending || data.incomplete);
            document.getElementById('statement-gross-warning').hidden = !data.missing_gross_count;
            status.textContent = `Indicateurs mis à jour à ${new Date().toLocaleTimeString('fr-FR')} · Actualisation toutes les 30 secondes.`;
        } catch (error) {
            status.textContent = 'Actualisation indisponible : les derniers montants affichés sont conservés. Réessayez ou reconnectez-vous.';
        } finally {
            clearTimeout(timeout);
            loading = false;
            button.disabled = false;
        }
    }
    button.addEventListener('click', refresh);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
    setInterval(refresh, 30000);
    refresh();
})();
