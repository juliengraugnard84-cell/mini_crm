document.addEventListener("DOMContentLoaded", () => {

    const input = document.getElementById("chatInput");
    const sendBtn = document.getElementById("chatSend");
    const fileInput = document.getElementById("chatUpload");
    const messagesBox = document.getElementById("chatMessages");

    if (!input || !sendBtn || !messagesBox) return;

    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content") || "";

    function escapeHTML(str) {
        const div = document.createElement("div");
        div.textContent = str ?? "";
        return div.innerHTML;
    }

    async function loadMessages() {
        try {
            const res = await fetch("/chat/messages?limit=80", { credentials: "same-origin" });
            const data = await res.json();

            messagesBox.innerHTML = "";

            (data.messages || []).forEach(m => {
                const div = document.createElement("div");
                div.className = "chat-message";

                let html = `<strong>${escapeHTML(m.username)}</strong> : ${escapeHTML(m.message || "")}`;
                if (m.file_url) {
                    const safeName = escapeHTML(m.file_name || "fichier");
                    html += ` <a href="${m.file_url}" target="_blank" rel="noopener noreferrer">📎 ${safeName}</a>`;
                }

                div.innerHTML = html;
                messagesBox.appendChild(div);
            });

            messagesBox.scrollTop = messagesBox.scrollHeight;
        } catch (e) {
            console.error("Erreur chargement messages", e);
        }
    }

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
        // compat CSRF form
        formData.append("csrf_token", csrfToken);

        try {
            const res = await fetch("/chat/send", {
                method: "POST",
                body: formData,
                credentials: "same-origin",
                headers: {
                    "X-CSRF-Token": csrfToken
                }
            });

            const data = await res.json();

            if (!data.success) {
                alert(data.message || "Erreur envoi message");
                return;
            }

            input.value = "";
            if (fileInput) fileInput.value = "";

            await loadMessages();
        } catch (e) {
            console.error("Erreur sendMessage", e);
            alert("Erreur réseau lors de l'envoi.");
        }
    }

    sendBtn.addEventListener("click", sendMessage);

    input.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
            e.preventDefault();
            sendMessage();
        }
    });

    loadMessages();
});
