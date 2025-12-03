// ============================================================
//                    CHAT WIDGET WHATSAPP PRO
// ============================================================

// Sélecteurs DOM
const chatBtn = document.getElementById("chat-widget-button");
const chatBox = document.getElementById("chat-widget-window");
const chatMessages = document.getElementById("chat-widget-messages");
const chatInput = document.getElementById("chat-widget-input");
const chatSend = document.getElementById("chat-widget-send");
const chatClose = document.getElementById("chat-widget-close");

// Sons WhatsApp-like
const sndSend = new Audio("/static/sounds/send.mp3");
const sndReceive = new Audio("/static/sounds/receive.mp3");

// Pour éviter doublons + effets son
let lastMessageId = 0;

// Palette de couleurs pour les autres utilisateurs
const userColors = {};
const palette = [
    "#f44336", "#e91e63", "#9c27b0", "#3f51b5",
    "#03a9f4", "#009688", "#8bc34a", "#ff9800"
];

function colorFor(username) {
    if (!userColors[username]) {
        userColors[username] = palette[Math.floor(Math.random() * palette.length)];
    }
    return userColors[username];
}

// ============================================================
//              OUVERTURE / FERMETURE DU CHAT
// ============================================================

chatBtn.onclick = () => {
    chatBox.style.display = "flex";
    loadMessages(true); // scroll bas
};

if (chatClose) {
    chatClose.onclick = () => {
        chatBox.style.display = "none";
    };
}

// ============================================================
//        FONCTION : Charger les messages depuis Flask
// ============================================================

async function loadMessages(forceScroll = false) {
    const res = await fetch("/chat/messages_json");
    const data = await res.json();

    let html = "";
    let newLastId = lastMessageId;

    data.forEach(m => {
        // Nouveau last ID
        if (m.id > newLastId) newLastId = m.id;

        // Son message reçu
        if (m.id > lastMessageId && !m.me) {
            sndReceive.play();
        }

        const bubbleColor = m.me ? "" : `style="border-left:4px solid ${colorFor(m.username)};"`;

        html += `
            <div class="chat-msg ${m.me ? "me" : "other"}" ${bubbleColor}>
                
                ${!m.me ? `<div><strong>${m.username}</strong></div>` : ""}

                <div>${m.content}</div>

                <div class="msg-time">
                    ${m.time}
                    ${m.me ? `<span class="msg-check">✔✔</span>` : ""}
                </div>
            </div>
        `;
    });

    const newMessages = newLastId > lastMessageId;
    lastMessageId = newLastId;

    chatMessages.innerHTML = html;

    if (forceScroll || newMessages) {
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }
}

// ============================================================
//               ENVOI MESSAGE
// ============================================================

async function sendMessage() {
    const text = chatInput.value.trim();
    if (!text) return;

    sndSend.play();

    await fetch("/chat/send_widget", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: text })
    });

    chatInput.value = "";
    loadMessages(true);
}

chatSend.onclick = sendMessage;

chatInput.addEventListener("keydown", e => {
    if (e.key === "Enter") {
        e.preventDefault();
        sendMessage();
    }
});

// ============================================================
//         "EN TRAIN D'ÉCRIRE..." (effet visuel client)
// ============================================================

let typingTimer;
const typingIndicator = document.getElementById("chat-typing");

chatInput.addEventListener("input", () => {
    if (!typingIndicator) return;
    typingIndicator.style.display = "block";

    clearTimeout(typingTimer);
    typingTimer = setTimeout(() => {
        typingIndicator.style.display = "none";
    }, 1000);
});

// ============================================================
//      AUTO-REFRESH toutes les 2 secondes si chat ouvert
// ============================================================

setInterval(() => {
    if (chatBox.style.display === "flex") {
        loadMessages(false);
    }
}, 2000);
