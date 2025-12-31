document.addEventListener("DOMContentLoaded", () => {

    /* ================= ELEMENTS ================= */

    const toggleBtn  = document.getElementById("chat-toggle");
    const widget     = document.getElementById("chat-widget");
    const closeBtn   = document.getElementById("chat-close");

    const form       = document.getElementById("chat-form");
    const input      = document.getElementById("chat-input");
    const fileInput  = document.getElementById("chat-file");
    const messagesBox= document.getElementById("chat-messages");
    const badge      = document.getElementById("chat-badge");

    const CURRENT_USER_ID = window.CHAT_CURRENT_USER_ID;
    const CSRF_TOKEN      = window.CHAT_CSRF_TOKEN;

    if (!toggleBtn || !widget || !form || !input || !messagesBox || !badge) {
        console.warn("Chat widget incomplet");
        return;
    }

    /* ================= STATE ================= */

    let lastSeenId  = 0;
    let unreadCount = 0;
    let isLoading   = false;

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
        const m = String(ts).match(/(\d{2}):(\d{2})/);
        return m ? `${m[1]}:${m[2]}` : "";
    }

    function scrollBottom() {
        messagesBox.scrollTop = messagesBox.scrollHeight;
    }

    function setBadge(n) {
        unreadCount = Math.max(0, n);
        if (unreadCount > 0) {
            badge.textContent = unreadCount;
            badge.style.display = "flex";
            toggleBtn.classList.add("chat-pulse");
        } else {
            badge.style.display = "none";
            toggleBtn.classList.remove("chat-pulse");
        }
    }

    function resetBadge() {
        setBadge(0);
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

        row.appendChild(bubble);
        return row;
    }

    /* ================= OPEN / CLOSE ================= */

    function setOpen(open) {
        if (open) {
            widget.classList.add("open");
            widget.setAttribute("aria-hidden", "false");
            resetBadge();
            loadMessages(true);
            setTimeout(() => input.focus(), 120);
        } else {
            widget.classList.remove("open");
            widget.setAttribute("aria-hidden", "true");
        }
    }

    toggleBtn.addEventListener("click", () => setOpen(!isOpen()));
    closeBtn.addEventListener("click", () => setOpen(false));

    /* ================= LOAD ================= */

    async function loadMessages(forceScroll = false) {
        if (isLoading) return;
        isLoading = true;

        try {
            const res = await fetch("/chat/messages?limit=120", {
                credentials: "same-origin"
            });
            const data = await res.json();
            const messages = data.messages || [];

            let maxId = lastSeenId;
            messages.forEach(m => {
                maxId = Math.max(maxId, Number(m.id || 0));
            });

            if (!isOpen() && maxId > lastSeenId) {
                const delta = messages.filter(m => Number(m.id) > lastSeenId).length;
                setBadge(unreadCount + delta);
            }

            messagesBox.innerHTML = "";
            messages.forEach(m => messagesBox.appendChild(renderMessage(m)));

            if (isOpen()) lastSeenId = maxId;
            if (forceScroll || isOpen()) scrollBottom();

        } catch (e) {
            console.error("Erreur chargement chat", e);
        } finally {
            isLoading = false;
        }
    }

    /* ================= SEND ================= */

    async function sendMessage() {
        const msg  = input.value.trim();
        const file = fileInput.files[0];

        if (!msg && !file) return;

        const fd = new FormData();
        if (msg) fd.append("message", msg);
        if (file) fd.append("file", file);

        const headers = {};
        if (CSRF_TOKEN) headers["X-CSRF-Token"] = CSRF_TOKEN;

        input.disabled = true;
        form.querySelector(".chat-send").disabled = true;

        try {
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
            fileInput.value = "";
            await loadMessages(true);

        } catch (e) {
            console.error("Erreur envoi chat", e);
            alert("Erreur réseau");
        } finally {
            input.disabled = false;
            form.querySelector(".chat-send").disabled = false;
            input.focus();
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

    /* ================= POLLING ================= */

    setInterval(() => loadMessages(false), 3000);
    loadMessages(false);
});
