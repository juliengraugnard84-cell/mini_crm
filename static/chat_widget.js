document.addEventListener("DOMContentLoaded", () => {

    /* ================= ELEMENTS ================= */

    const bubble = document.getElementById("chat-toggle");
    const win = document.getElementById("chat-widget");
    const closeBtn = document.getElementById("chat-close");

    const form = document.getElementById("chat-form");
    const input = document.getElementById("chat-input");
    const fileInput = document.getElementById("chat-file");
    const messagesBox = document.getElementById("chat-messages");

    let lastMessageCount = 0;
    let unreadCount = 0;

    if (!bubble || !win || !form || !input || !messagesBox) {
        console.warn("Chat widget incomplet");
        return;
    }

    /* ================= BADGE ================= */

    const badge = document.createElement("div");
    badge.className = "chat-badge";
    badge.style.display = "none";
    bubble.appendChild(badge);

    function updateBadge() {
        if (unreadCount > 0) {
            badge.textContent = unreadCount;
            badge.style.display = "flex";

            // 🔥 clignotement actif
            bubble.classList.add("chat-pulse");
        } else {
            badge.style.display = "none";

            // arrêt clignotement
            bubble.classList.remove("chat-pulse");
        }
    }

    function resetBadge() {
        unreadCount = 0;
        updateBadge();
    }

    /* ================= TOGGLE ================= */

    bubble.addEventListener("click", () => {
        const isOpen = win.classList.contains("open");
        win.classList.toggle("open", !isOpen);

        if (!isOpen) {
            resetBadge();
            loadMessages(true);
            setTimeout(() => input.focus(), 150);
        }
    });

    if (closeBtn) {
        closeBtn.addEventListener("click", () => {
            win.classList.remove("open");
        });
    }

    /* ================= HELPERS ================= */

    function escapeHTML(str) {
        const div = document.createElement("div");
        div.textContent = str ?? "";
        return div.innerHTML;
    }

    /* ================= LOAD ================= */

    async function loadMessages(forceOpen = false) {
        try {
            const res = await fetch("/chat/messages?limit=80", {
                credentials: "same-origin"
            });

            const data = await res.json();
            const messages = data.messages || [];

            if (messages.length > lastMessageCount) {
                const diff = messages.length - lastMessageCount;

                if (!win.classList.contains("open")) {
                    unreadCount += diff;
                    updateBadge();
                }
            }

            lastMessageCount = messages.length;
            messagesBox.innerHTML = "";

            messages.forEach(m => {
                const div = document.createElement("div");
                div.className = "chat-message";

                let html = `<strong>${escapeHTML(m.username)}</strong> : ${escapeHTML(m.message || "")}`;

                if (m.file_url) {
                    const safeName = escapeHTML(m.file_name || "fichier");
                    html += ` <a href="${m.file_url}" target="_blank" rel="noopener">📎 ${safeName}</a>`;
                }

                div.innerHTML = html;
                messagesBox.appendChild(div);
            });

            messagesBox.scrollTop = messagesBox.scrollHeight;

        } catch (e) {
            console.error("Erreur chargement chat", e);
        }
    }

    /* ================= SEND ================= */

    async function sendMessage() {

        const message = input.value.trim();
        const file = fileInput.files[0];

        if (!message && !file) {
            alert("Message ou fichier requis");
            return;
        }

        const formData = new FormData();
        if (message) formData.append("message", message);
        if (file) formData.append("file", file);

        try {
            const res = await fetch("/chat/send", {
                method: "POST",
                body: formData,
                credentials: "same-origin"
            });

            const data = await res.json();

            if (!data.success) {
                alert(data.message || "Erreur envoi message");
                return;
            }

            input.value = "";
            fileInput.value = "";

            loadMessages(true);

        } catch (e) {
            console.error("Erreur send chat", e);
            alert("Erreur réseau");
        }
    }

    form.addEventListener("submit", e => {
        e.preventDefault();
        sendMessage();
    });

    input.addEventListener("keydown", e => {
        if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });

    /* ================= AUTO REFRESH ================= */

    setInterval(() => {
        loadMessages(false);
    }, 5000);

});
