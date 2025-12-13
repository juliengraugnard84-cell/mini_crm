document.addEventListener("DOMContentLoaded", () => {

    const input = document.getElementById("chatInput");
    const sendBtn = document.getElementById("chatSend");
    const fileInput = document.getElementById("chatUpload");
    const messagesBox = document.getElementById("chatMessages");

    async function loadMessages() {
        const res = await fetch("/chat/messages");
        const data = await res.json();

        messagesBox.innerHTML = "";

        data.messages.forEach(m => {
            const div = document.createElement("div");
            div.className = "chat-line";

            let html = `<strong>${m.username}</strong> : ${m.message || ""}`;
            if (m.file_url) {
                html += ` <a href="${m.file_url}" target="_blank">📎 ${m.file_name}</a>`;
            }

            div.innerHTML = html;
            messagesBox.appendChild(div);
        });

        messagesBox.scrollTop = messagesBox.scrollHeight;
    }

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

        const res = await fetch("/chat/send", {
            method: "POST",
            body: formData
        });

        const data = await res.json();

        if (!data.success) {
            alert(data.message || "Erreur envoi message");
            return;
        }

        input.value = "";
        fileInput.value = "";

        loadMessages();
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
