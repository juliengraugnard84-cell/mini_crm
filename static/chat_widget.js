document.addEventListener("DOMContentLoaded", () => {

    const bubble = document.getElementById("chatBubble");
    const win = document.getElementById("chatWindow");
    const closeBtn = document.getElementById("chatClose");

    const input = document.getElementById("chatInput");
    const sendBtn = document.getElementById("chatSend");
    const fileInput = document.getElementById("chatUpload");
    const messagesBox = document.getElementById("chatMessages");

    if (!bubble || !win || !input || !sendBtn || !messagesBox) {
        console.warn("Chat widget incomplet");
        return;
    }

    /* ================= TOGGLE ================= */

    bubble.addEventListener("click", () => {
        win.style.display = win.style.display === "flex" ? "none" : "flex";
        if (win.style.display === "flex") {
            loadMessages();
        }
    });

    closeBtn.addEventListener("click", () => {
        win.style.display = "none";
    });

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
                    html += ` <a href="${m.file_url}" target="_blank">📎 ${safeName}</a>`;
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

            loadMessages();

        } catch (e) {
            console.error("Erreur send chat", e);
            alert("Erreur réseau");
        }
    }

    sendBtn.addEventListener("click", sendMessage);

    input.addEventListener("keydown", e => {
        if (e.key === "Enter") {
            e.preventDefault();
            sendMessage();
        }
    });

});
