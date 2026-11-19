document.addEventListener('click', event => {
    const menu = event.target.closest('.crm-mobile-menu');
    if (menu) {
        const open = document.body.classList.toggle('navigation-open');
        menu.setAttribute('aria-expanded', String(open));
        return;
    }
    const trigger = event.target.closest('[data-open-details]');
    if (!trigger) return;
    const panel = document.getElementById(trigger.dataset.openDetails);
    if (panel instanceof HTMLDetailsElement) panel.open = true;
});
document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && document.body.classList.contains('navigation-open')) {
        document.body.classList.remove('navigation-open');
        const menu = document.querySelector('.crm-mobile-menu');
        menu.setAttribute('aria-expanded', 'false');
        menu.focus();
    }
});
