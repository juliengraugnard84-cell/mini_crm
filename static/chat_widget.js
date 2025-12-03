let chatOpen = false;

document.addEventListener("DOMContentLoaded", () => {

    const btn = document.getElementById("chat-button");
    const win = document.getElementById("chat-window");
    const close = document.getElementById("chat-close");
    const messagesBox = document.getElementById("chat-messages");
    const input = document.getElementById("chat-text");
    const sendBtn = document.getElementById("chat-send");

    // 🔥 Assurer que la fenêtre est fermée au départ
    win.classList.add("hidden");
    chatOpen = false;

    /* ==================== FONCTIONS ==================== */

    function refreshMessages() {
        fetch("/chat/messages_json")
            .then(res => res.json())
            .then(data => {
                messagesBox.innerHTML = "";

                data.forEach(m => {
                    const div = document.createElement("div");
                    div.classList.add("msg");
                    div.classList.add(m.me ? "me" : "other");
                    div.textContent = m.username + " : " + m.content;
                    messagesBox.appendChild(div);
                });

                messagesBox.scrollTop = messagesBox.scrollHeight;
            });
    }

    function openChat() {
        chatOpen = true;
        win.classList.remove("hidden");
        refreshMessages();
    }

    function closeChat() {
        chatOpen = false;
        win.classList.add("hidden");
    }

    function sendMessage() {
        const txt = input.value.trim();
        if (!txt) return;

        fetch("/chat/send_widget", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: txt })
        }).then(() => {
            input.value = "";
            refreshMessages();
        });
    }

    /* ==================== EVENTS ==================== */

    btn.addEventListener("click", () => {
        if (chatOpen) closeChat();
        else openChat();
    });

    close.addEventListener("click", closeChat);

    sendBtn.addEventListener("click", sendMessage);

    input.addEventListener("keypress", e => {
        if (e.key === "Enter") sendMessage();
    });

    // Auto refresh si la fenêtre est ouverte
    setInterval(() => {
        if (chatOpen) refreshMessages();
    }, 3000);
});
