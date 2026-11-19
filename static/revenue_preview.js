(() => {
    const amount = document.getElementById('revenue-amount');
    const source = document.getElementById('revenue-source');
    const preview = document.getElementById('revenue-preview');
    if (!amount || !source || !preview) return;
    const money = cents => (cents / 100).toLocaleString('fr-FR', {style: 'currency', currency: 'EUR'});
    function update() {
        const value = amount.value.replace(/[\s\u202f\u00a0]/g, '').replace(',', '.');
        const percent = Number(source.value === 'ade' ? preview.dataset.retentionAde : source.value === 'direct' ? preview.dataset.retentionDirect : 0);
        if (!/^\d+(\.\d{1,2})?$/.test(value) || !percent || Number(value) <= 0) {
            preview.textContent = "Saisissez la somme initiale et choisissez l'origine pour voir le calcul.";
            return;
        }
        const cents = Math.round(Number(value) * 100);
        const retained = Math.round(cents * percent / 100);
        const net = cents - retained;
        const rate = preview.dataset[source.value];
        let text = `Retenue fournisseur : ${money(retained)} · CA net Aléo : ${money(net)}`;
        if (rate !== undefined && rate !== '') {
            const commission = Math.round(net * Number(rate) / 100);
            text += ` · Commission commercial (${rate} %) : ${money(commission)} · Solde Aléo : ${money(net - commission)}`;
        } else {
            text += ' · Taux commercial non configuré pour cette origine : configurez-le avant validation pour calculer les commissions.';
        }
        preview.textContent = text;
    }
    amount.addEventListener('input', update);
    source.addEventListener('change', update);
    update();
})();
