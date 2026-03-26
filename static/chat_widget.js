document.addEventListener("DOMContentLoaded", () => {

    /* ================= ROOT WIDGET (FIX CRITIQUE) ================= */

    const widget = document.getElementById("chat-widget");

    if (!widget) {
        console.warn("Chat widget absent");
        return;
    }

    /* ================= ELEMENTS (SCOPED FIX) ================= */

    const toggleBtn   = document.getElementById("chat-toggle");
    const closeBtn    = widget.querySelector("#chat-close");

    const form        = widget.querySelector("#chat-form");
    const input       = widget.querySelector("#chat-input");
    const fileInput   = widget.querySelector("#chat-file");
    const messagesBox = widget.querySelector("#chat-messages");
    const badge       = document.getElementById("chat-badge");

    const CURRENT_USER_ID = window.CHAT_CURRENT_USER_ID ?? null;
    const CSRF_TOKEN      = window.CHAT_CSRF_TOKEN ?? null;
    const CAN_UPLOAD      = window.CHAT_CAN_UPLOAD ?? false;

    const audio = document.getElementById("chat-sound");

    /* ================= DEBUG ================= */

    console.log("FORM =", form);
    console.log("FILE INPUT =", fileInput);

    if (fileInput) {
        fileInput.addEventListener("change", () => {
            console.log("📂 fichiers sélectionnés :", fileInput.files);
        });
    }

    /* ================= SÉCURITÉ ================= */

    if (!toggleBtn || !form || !input || !messagesBox) {
        console.warn("Chat widget incomplet — initialisation annulée");
        return;
    }

    /* ================= STATE ================= */

    let isLoading = false;
    let isSending = false;
    let audioUnlocked = false;
    let lastSoundTime = 0;

    let lastMessageId = null;
    let isFirstLoad = true;

    /* ================= AUDIO ================= */

    function unlockAudio() {
        if (!audio || audioUnlocked) return;

        audio.play().then(() => {
            audio.pause();
            audio.currentTime = 0;
            audioUnlocked = true;
        }).catch(() => {});
    }

    document.addEventListener("click", unlockAudio);
    document.addEventListener("keydown", unlockAudio);
    window.addEventListener("focus", unlockAudio);

    function playSound() {
        if (!audio || !audioUnlocked) return;

        const now = Date.now();
        if (now - lastSoundTime < 800) return;

        lastSoundTime = now;
        audio.currentTime = 0;
        audio.play().catch(() => {});
    }

    /* ================= HELPERS ================= */

    function isOpen() {
        return widget.classList.contains("open");
    }

    function escapeHTML(str) {
        const div = document.createElement("div");
        div.textContent = str ?? "";
        return div.innerHTML;
    }

    function formatTime(ts) {
        if (!ts) return "";

        const date = new Date(ts);

        return date.toLocaleTimeString("fr-FR", {
            hour: "2-digit",
            minute: "2-digit",
            timeZone: "Europe/Paris"
        });
    }

    function scrollBottom() {
        messagesBox.scrollTop = messagesBox.scrollHeight;
    }

    function setBadge(count) {
        if (!badge) return;

        const n = Math.max(0, count);

        if (n > 0) {
            badge.textContent = n;
            badge.style.display = "flex";
            toggleBtn.classList.add("chat-pulse");
        } else {
            badge.style.display = "none";
            toggleBtn.classList.remove("chat-pulse");
        }
    }

    function getLatestMessageId(messages) {
        if (!Array.isArray(messages) || messages.length === 0) return null;

        let maxId = null;

        for (const m of messages) {
            const id = Number(m.id);
            if (!Number.isNaN(id) && (maxId === null || id > maxId)) {
                maxId = id;
            }
        }

        return maxId;
    }

    function hasNewIncomingMessage(messages) {
        if (!Array.isArray(messages) || messages.length === 0) return false;
        if (lastMessageId === null) return false;

        return messages.some(m => {
            const messageId = Number(m.id);
            const senderId = Number(m.user_id);

            return (
                !Number.isNaN(messageId) &&
                messageId > lastMessageId &&
                senderId !== Number(CURRENT_USER_ID)
            );
        });
    }

    /* ================= RENDER ================= */

    function renderMessage(m) {
        const mine = CURRENT_USER_ID !== null &&
                     Number(m.user_id) === Number(CURRENT_USER_ID);

        const row = document.createElement("div");
        row.className = `chat-row ${mine ? "me" : "them"}`;

        const bubble = document.createElement("div");
        bubble.className = `chat-bubble ${mine ? "me" : "them"}`;

        const meta = document.createElement("div");
        meta.className = "chat-meta";
        meta.innerHTML = `
            <span class="chat-user">${escapeHTML(mine ? "Vous" : m.username)}</span>
            <span class="chat-time">${escapeHTML(formatTime(m.created_at))}</span>
        `;
        bubble.appendChild(meta);

        if (m.message) {
            const text = document.createElement("div");
            text.className = "chat-text";
            text.innerHTML = escapeHTML(m.message);
            bubble.appendChild(text);
        }

        if (m.file_url) {
            const file = document.createElement("a");
            file.className = "chat-file";
            file.href = m.file_url;
            file.target = "_blank";
            file.rel = "noopener";
            file.innerHTML = `📎 ${escapeHTML(m.file_name || "fichier")}`;
            bubble.appendChild(file);
        }

        if (mine) {
            const status = document.createElement("div");
            status.className = "chat-status";
            status.innerHTML = m.is_read
                ? `<span class="chat-read read">✓✓</span>`
                : `<span class="chat-read sent">✓</span>`;
            bubble.appendChild(status);
        }

        row.appendChild(bubble);
        return row;
    }

    /* ================= MARK AS READ ================= */

    async function markAsRead() {
        try {
            const headers = {};
            if (CSRF_TOKEN) headers["X-CSRF-Token"] = CSRF_TOKEN;

            await fetch("/chat/mark_read", {
                method: "POST",
                credentials: "same-origin",
                headers
            });

            console.log("✔ messages marqués comme lus");

        } catch (e) {
            console.error("Erreur mark_read", e);
        }
    }

    /* ================= OPEN / CLOSE ================= */

    function openChat() {
        widget.classList.add("open");
        widget.setAttribute("aria-hidden", "false");
        toggleBtn.setAttribute("aria-expanded", "true");

        setBadge(0);

        loadMessages(true);
        markAsRead(); // ✅ FIX BADGE

        setTimeout(() => input.focus(), 100);
    }

    function closeChat() {
        widget.classList.remove("open");
        widget.setAttribute("aria-hidden", "true");
        toggleBtn.setAttribute("aria-expanded", "false");
    }

    toggleBtn.addEventListener("click", () => {
        if (isOpen()) closeChat();
        else openChat();
    });

    if (closeBtn) {
        closeBtn.addEventListener("click", closeChat);
    }

    /* ================= LOAD ================= */

    async function loadMessages(forceScroll = false) {
        if (isLoading) return;
        isLoading = true;

        try {
            const res = await fetch("/chat/messages?limit=120", {
                credentials: "same-origin"
            });

            const data = await res.json();
            const messages = Array.isArray(data.messages) ? data.messages : [];

            if (!isFirstLoad && hasNewIncomingMessage(messages)) {
                playSound();
            }

            const unread = messages.filter(
                m => !m.is_read && Number(m.user_id) !== Number(CURRENT_USER_ID)
            ).length;

            if (!isOpen()) setBadge(unread);

            messagesBox.innerHTML = "";
            messages.forEach(m => messagesBox.appendChild(renderMessage(m)));

            if (forceScroll || isOpen()) scrollBottom();

            const latestId = getLatestMessageId(messages);
            if (latestId !== null) lastMessageId = latestId;

            if (isFirstLoad) isFirstLoad = false;

        } catch (e) {
            console.error("Erreur chargement chat", e);
        } finally {
            isLoading = false;
        }
    }

    /* ================= SEND (FIX TOTAL) ================= */

    async function sendMessage() {

        if (isSending) return;

        const msg   = input.value.trim();
        const files = fileInput?.files ? Array.from(fileInput.files) : [];

        if (!msg && files.length === 0) return;

        if (files.length > 0 && !CAN_UPLOAD) {
            alert("Vous n’êtes pas autorisé à envoyer des fichiers.");
            return;
        }

        isSending = true;

        const fd = new FormData();

        if (msg) fd.append("message", msg);

        files.forEach(f => {
            fd.append("file", f);
        });

        const headers = {};
        if (CSRF_TOKEN) headers["X-CSRF-Token"] = CSRF_TOKEN;

        const sendBtn = form.querySelector(".chat-send");

        input.disabled = true;
        if (sendBtn) sendBtn.disabled = true;
        if (fileInput) fileInput.disabled = true;

        try {

            console.log("📤 Envoi :", files);

            const res = await fetch("/chat/send", {
                method: "POST",
                body: fd,
                credentials: "same-origin",
                headers
            });

            const data = await res.json();

            if (!data.success) {
                alert(data.message || "Erreur envoi message");
                return;
            }

            input.value = "";
            if (fileInput) fileInput.value = "";

            await loadMessages(true);

        } catch (e) {
            console.error("Erreur envoi chat", e);
            alert("Erreur envoi");
        } finally {

            input.disabled = false;
            if (sendBtn) sendBtn.disabled = false;
            if (fileInput) fileInput.disabled = false;

            isSending = false;
            input.focus();
        }
    }

    form.addEventListener("submit", e => {
        console.log("🚀 SUBMIT TRIGGERED");
        e.preventDefault();
        sendMessage();
    });

    /* ================= INIT ================= */

    setInterval(() => {
        loadMessages(false);

        if (isOpen()) {
            markAsRead(); // ✅ sync temps réel
        }

    }, 5000);

    loadMessages(false);
});