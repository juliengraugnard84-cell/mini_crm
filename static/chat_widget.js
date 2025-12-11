/* =======================================================
   CHAT WIDGET — Version complète & optimisée
   Compatible Cloudinary, WhatsApp-like, 2025
======================================================= */


/* -------------------------------------------------------
   OUVERTURE / FERMETURE DU CHAT
------------------------------------------------------- */

function openChatWidget() {
    const area = document.getElementById("chat-widget");
    if (!area) return;

    area.style.display = "flex";
    loadMessages(); // charge les messages dès l’ouverture
}

function closeChatWidget() {
    const area = document.getElementById("chat-widget");
    if (!area) return;

    area.style.display = "none";
}


/* -------------------------------------------------------
   ENVOI DE MESSAGE TEXTE
------------------------------------------------------- */

function sendWidgetMessage() {
    const input = document.getElementById("chat-input");
    if (!input) return;

    const msg = input.value.trim();
    if (!msg) return;

    fetch("/chat/send_widget", {
        method: "POST",
        body: JSON.stringify({ message: msg }),
        headers: { "Content-Type": "application/json" }
    })
    .then(() => {
        input.value = "";
        loadMessages();
    })
    .catch(err => console.error("Erreur message chat :", err));
}


/* -------------------------------------------------------
   UPLOAD DE FICHIER (Cloudinary)
------------------------------------------------------- */

function uploadChatFile() {
    const fileInput = document.getElementById("file-input");
    if (!fileInput || !fileInput.files.length) return;

    const file = fileInput.files[0];
    const formData = new FormData();
    formData.append("file", file);

    fetch("/chat/upload_file", {
        method: "POST",
        body: formData
    })
    .then(r => r.json())
    .then(res => {
        if (!res.success) {
            console.error("Erreur upload:", res.error);
            return;
        }
        fileInput.value = ""; // reset champ
        loadMessages();
    })
    .catch(err => console.error("Erreur upload chat :", err));
}


/* -------------------------------------------------------
   CHARGEMENT DES MESSAGES
   - Affiche texte
   - Affiche images (Cloudinary)
   - Affiche fichiers (PDF, Word, etc.)
------------------------------------------------------- */

function loadMessages() {
    fetch("/chat/messages_json")
        .then(r => r.json())
        .then(messages => {
            const box = document.getElementById("chat-messages");
            if (!box) return;

            box.innerHTML = "";

            messages.forEach(m => {
                const div = document.createElement("div");
                div.className = m.me ? "message me" : "message";

                let html = "";

                // Message texte
                if (m.content && m.content.trim() !== "") {
                    html += `<div>${m.content}</div>`;
                }

                // Fichier / Image
                if (m.file_url) {
                    const isImage = /\.(png|jpe?g|gif|webp)$/i.test(m.file_url);

                    if (isImage) {
                        html += `
                            <div style="margin-top:6px;">
                                <img src="${m.file_url}" class="chat-image" alt="${m.file_name}">
                            </div>
                        `;
                    } else {
                        html += `
                            <div style="margin-top:6px;">
                                <a href="${m.file_url}" class="message-file" target="_blank">
                                    📎 ${m.file_name}
                                </a>
                            </div>
                        `;
                    }
                }

                // Meta (username + heure)
                html += `<div class="msg-meta">${m.username} • ${m.time}</div>`;

                div.innerHTML = html;
                box.appendChild(div);
            });

            // Scroll automatique vers le bas
            box.scrollTop = box.scrollHeight;
        })
        .catch(err => console.error("Erreur chargement chat :", err));
}


/* -------------------------------------------------------
   AUTO-REFRESH du chat (1.5 sec)
------------------------------------------------------- */

setInterval(loadMessages, 1500);

// Charge messages automatiquement au chargement de la page
document.addEventListener("DOMContentLoaded", loadMessages);
