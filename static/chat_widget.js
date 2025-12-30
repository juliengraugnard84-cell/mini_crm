document.addEventListener("DOMContentLoaded", () => {

    /* ================= ELEMENTS ================= */

    const bubble = document.getElementById("chat-bubble");
    const panel = document.getElementById("chat-panel");
    const closeBtn = document.getElementById("chat-close");

    const form = document.getElementById("chat-form");
    const input = document.getElementById("chat-input");
    const fileInput = document.getElementById("chat-file");
    const messagesBox = document.getElementById("chat-messages");

    if (!bubble || !panel || !form || !input || !messagesBox) {
        console.warn("Chat widget incomplet");
        return;
    }

    /* ================= TOGGLE ================= */

    bubble.addEventListener("click", () => {
        const isHidden = panel.classList.contains("chat-hidden");

        panel.classList.toggle("chat-hidden", !isHidden);

        if (isHidden) {
            loadMessages();
            setTimeout(() => input.focus(), 150);
        }
    });

    if (closeBtn) {
        closeBtn.addEventListener("click", () => {
            panel.classList.add("chat-hidden");
        });
    }

    /* ================= HELPERS ================= */

    function escapeHTML(str) {
        const div = document.createElement("div");
        div.textContent = str ?? "";
        return div.innerHTML;
    }

    /* ================= LOAD ================= */

    async function loadMessages() {
        try {
            const res = await fetch("/chat/messages?limit=80", {
                credentials: "same-origin"
            });

            const data = await res.json();
            messagesBox.innerHTML = "";

            (data.messages || []).forEach(m => {
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
        const file = fileInput?.files?.[0];

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
            if (fileInput) fileInput.value = "";

            loadMessages();

        } catch (e) {
            console.error("Erreur send chat", e);
            alert("Erreur réseau");
        }
    }

    /* ================= EVENTS ================= */

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

});
