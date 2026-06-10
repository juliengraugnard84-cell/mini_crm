document.addEventListener("DOMContentLoaded", () => {
    const widget = document.getElementById("chat-widget");

    if (!widget) {
        return;
    }

    const toggleBtn = document.getElementById("chat-toggle");
    const closeBtn = document.getElementById("chat-close");
    const refreshBtn = document.getElementById("chat-refresh");
    const form = document.getElementById("chat-form");
    const input = document.getElementById("chat-input");
    const fileInput = document.getElementById("chat-file");
    const messagesBox = document.getElementById("chat-messages");
    const badge = document.getElementById("chat-badge");
    const recipientSelect = document.getElementById("chat-recipient");
    const quickRecipients = document.getElementById("chat-quick-recipients");
    const contextBanner = document.getElementById("chat-context-banner");
    const previewBox = document.getElementById("chat-preview");
    const fileMeta = document.getElementById("chat-file-meta");
    const sendBtn = form ? form.querySelector(".chat-send") : null;

    const CURRENT_USER_ID = normalizeId(window.CHAT_CURRENT_USER_ID);
    const CURRENT_USERNAME = window.CHAT_CURRENT_USERNAME || "Vous";
    const CURRENT_USER_ROLE = window.CHAT_CURRENT_USER_ROLE || null;
    const CSRF_TOKEN = window.CHAT_CSRF_TOKEN || null;
    const CAN_UPLOAD = window.CHAT_CAN_UPLOAD ?? false;
    const receiveAudio = document.getElementById("chat-sound-receive");
    const sendAudio = document.getElementById("chat-sound-send");
    const RECIPIENT_STORAGE_KEY = "mini_crm_chat_recipient";

    if (!toggleBtn || !form || !input || !messagesBox || !recipientSelect) {
        return;
    }

    const state = {
        recipients: [],
        currentUser: null,
        isBootstrapLoaded: false,
        isLoading: false,
        isSending: false,
        isFirstLoad: true,
        audioUnlocked: false,
        lastReceiveSoundAt: 0,
        lastMessageId: null,
        lastRenderedSignature: "",
        pollTimer: null,
    };

    function normalizeId(value) {
        const num = Number(value);
        return Number.isFinite(num) ? num : null;
    }

    function escapeHTML(value) {
        const div = document.createElement("div");
        div.textContent = value ?? "";
        return div.innerHTML;
    }

    function isOpen() {
        return widget.classList.contains("open");
    }

    async function parseJSONResponse(response, fallbackMessage) {
        const contentType = (response.headers.get("content-type") || "").toLowerCase();

        if (contentType.includes("application/json")) {
            return response.json();
        }

        const rawText = await response.text();
        const trimmedText = rawText.trim();

        if (trimmedText.startsWith("<")) {
            throw new Error(fallbackMessage || `HTTP ${response.status}`);
        }

        const compactText = rawText
            .replace(/<[^>]*>/g, " ")
            .replace(/\s+/g, " ")
            .trim();

        throw new Error(compactText || fallbackMessage || `HTTP ${response.status}`);
    }

    function parseChatDate(value) {
        if (!value) {
            return null;
        }

        const raw = String(value).trim();
        const match = raw.match(
            /^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?)?$/
        );

        if (match) {
            return new Date(
                Number(match[1]),
                Number(match[2]) - 1,
                Number(match[3]),
                Number(match[4] || 0),
                Number(match[5] || 0),
                Number(match[6] || 0)
            );
        }

        const parsed = new Date(raw);
        return Number.isNaN(parsed.getTime()) ? null : parsed;
    }

    function formatTime(value) {
        const date = parseChatDate(value);

        if (!date) {
            return "";
        }

        return date.toLocaleTimeString("fr-FR", {
            hour: "2-digit",
            minute: "2-digit",
        });
    }

    function formatDayLabel(value) {
        const date = parseChatDate(value);

        if (!date) {
            return "";
        }

        const today = new Date();
        const startOfToday = new Date(today.getFullYear(), today.getMonth(), today.getDate());
        const startOfTarget = new Date(date.getFullYear(), date.getMonth(), date.getDate());
        const diffDays = Math.round((startOfTarget - startOfToday) / 86400000);

        if (diffDays === 0) {
            return "Aujourd'hui";
        }

        if (diffDays === -1) {
            return "Hier";
        }

        return date.toLocaleDateString("fr-FR", {
            day: "2-digit",
            month: "short",
            year: today.getFullYear() === date.getFullYear() ? undefined : "numeric",
        });
    }

    function formatRoleLabel(role, fallbackLabel) {
        if (fallbackLabel) {
            return fallbackLabel;
        }

        if (role === "admin") {
            return "Admin";
        }

        if (role === "commercial") {
            return "Commercial";
        }

        return "Utilisateur";
    }

    function getInitials(name) {
        const chunks = String(name || "")
            .trim()
            .split(/\s+/)
            .filter(Boolean)
            .slice(0, 2);

        if (chunks.length === 0) {
            return "??";
        }

        return chunks.map((chunk) => chunk[0].toUpperCase()).join("");
    }

    function autoResizeInput() {
        input.style.height = "auto";
        input.style.height = `${Math.min(input.scrollHeight, 140)}px`;
    }

    function setBadge(count) {
        if (!badge) {
            return;
        }

        const safeCount = Math.max(0, Number(count) || 0);

        if (safeCount > 0) {
            badge.textContent = safeCount > 99 ? "99+" : String(safeCount);
            badge.style.display = "flex";
            toggleBtn.classList.add("chat-pulse");
        } else {
            badge.style.display = "none";
            toggleBtn.classList.remove("chat-pulse");
        }
    }

    function scrollBottom() {
        messagesBox.scrollTop = messagesBox.scrollHeight;
    }

    function saveRecipientSelection(value) {
        try {
            window.localStorage.setItem(RECIPIENT_STORAGE_KEY, value || "all");
        } catch (_error) {
            // ignore
        }
    }

    function loadStoredRecipient() {
        try {
            return window.localStorage.getItem(RECIPIENT_STORAGE_KEY) || "all";
        } catch (_error) {
            return "all";
        }
    }

    function getSelectedRecipientOption() {
        if (!recipientSelect) {
            return null;
        }

        return recipientSelect.options[recipientSelect.selectedIndex] || null;
    }

    function getRecipientById(rawId) {
        const id = String(rawId ?? "");

        return state.recipients.find((recipient) => String(recipient.id) === id) || null;
    }

    function updateContextBanner() {
        const recipientId = recipientSelect.value || "all";

        if (recipientId === "all") {
            const roleLabel = formatRoleLabel(CURRENT_USER_ROLE, state.currentUser?.role_label);
            contextBanner.textContent = `Diffusion a toute l'equipe depuis le canal ${roleLabel}`;
            contextBanner.dataset.mode = "broadcast";
        } else {
            const recipient = getRecipientById(recipientId);
            const recipientName = recipient ? recipient.username : "Destinataire";
            const recipientRole = formatRoleLabel(recipient?.role, recipient?.role_label);
            contextBanner.textContent = `Message prive a ${recipientName} (${recipientRole})`;
            contextBanner.dataset.mode = "direct";
        }
    }

    function renderQuickRecipients() {
        if (!quickRecipients) {
            return;
        }

        const selectedValue = recipientSelect.value || "all";
        const fragment = document.createDocumentFragment();
        const chipEntries = [{ id: "all", username: "Equipe" }]
            .concat(state.recipients.slice(0, 5));

        quickRecipients.innerHTML = "";

        chipEntries.forEach((entry) => {
            const chip = document.createElement("button");
            chip.type = "button";
            chip.className = "chat-quick-chip";
            chip.dataset.value = String(entry.id);
            chip.textContent = entry.id === "all"
                ? entry.username
                : `${entry.username} (${formatRoleLabel(entry.role, entry.role_label)})`;

            if (String(entry.id) === selectedValue) {
                chip.classList.add("active");
            }

            chip.addEventListener("click", () => {
                recipientSelect.value = String(entry.id);
                saveRecipientSelection(String(entry.id));
                updateContextBanner();
                renderQuickRecipients();
            });

            fragment.appendChild(chip);
        });

        quickRecipients.appendChild(fragment);
    }

    function populateRecipients(recipients) {
        const previousValue = recipientSelect.value || loadStoredRecipient();
        const validRecipients = Array.isArray(recipients) ? recipients : [];

        state.recipients = validRecipients;
        recipientSelect.innerHTML = "";

        const allOption = document.createElement("option");
        allOption.value = "all";
        allOption.textContent = "Toute l'equipe";
        recipientSelect.appendChild(allOption);

        validRecipients.forEach((recipient) => {
            const option = document.createElement("option");
            option.value = String(recipient.id);
            option.textContent = `${recipient.username} (${formatRoleLabel(recipient.role, recipient.role_label)})`;
            recipientSelect.appendChild(option);
        });

        const optionValues = Array.from(recipientSelect.options).map((option) => option.value);
        recipientSelect.value = optionValues.includes(previousValue) ? previousValue : "all";

        updateContextBanner();
        renderQuickRecipients();
    }

    function unlockAudio() {
        if (state.audioUnlocked) {
            return;
        }

        const audioCandidates = [receiveAudio, sendAudio].filter(Boolean);

        if (audioCandidates.length === 0) {
            state.audioUnlocked = true;
            return;
        }

        Promise.allSettled(
            audioCandidates.map((audio) =>
                audio.play().then(() => {
                    audio.pause();
                    audio.currentTime = 0;
                })
            )
        ).finally(() => {
            state.audioUnlocked = true;
        });
    }

    function playReceiveSound() {
        if (!receiveAudio || !state.audioUnlocked) {
            return;
        }

        const now = Date.now();

        if (now - state.lastReceiveSoundAt < 1200) {
            return;
        }

        state.lastReceiveSoundAt = now;
        receiveAudio.currentTime = 0;
        receiveAudio.play().catch(() => {});
    }

    function playSendSound() {
        if (!sendAudio || !state.audioUnlocked) {
            return;
        }

        sendAudio.currentTime = 0;
        sendAudio.play().catch(() => {});
    }

    function updateFilePreview() {
        const files = fileInput && fileInput.files ? Array.from(fileInput.files) : [];

        if (previewBox) {
            previewBox.innerHTML = "";
        }

        if (!fileMeta) {
            return;
        }

        if (files.length === 0) {
            fileMeta.textContent = "Aucun fichier selectionne";
            return;
        }

        fileMeta.textContent =
            files.length === 1
                ? files[0].name
                : `${files.length} fichiers prets a l'envoi`;

        const fragment = document.createDocumentFragment();

        files.forEach((file) => {
            const item = document.createElement("div");
            item.className = "chat-preview-item";
            item.textContent = `Fichier: ${file.name}`;
            fragment.appendChild(item);
        });

        if (previewBox) {
            previewBox.appendChild(fragment);
        }
    }

    function buildMessageScopeLabel(message, mine) {
        const scope = message.scope || "broadcast";

        if (scope === "direct") {
            if (mine) {
                const targetRole = formatRoleLabel(
                    message.recipient_role,
                    message.recipient_role_label
                );
                return `A ${message.recipient_username || "un destinataire"} (${targetRole})`;
            }

            const senderRole = formatRoleLabel(message.user_role, message.user_role_label);
            return `Prive ${senderRole}`;
        }

        return "Equipe";
    }

    function renderEmptyState() {
        messagesBox.innerHTML = `
            <div class="chat-empty">
                <div class="chat-empty-title">Aucun message pour le moment</div>
                <div class="chat-empty-text">Choisissez un destinataire puis lancez la conversation.</div>
            </div>
        `;
    }

    function renderMessage(message) {
        const mine = normalizeId(message.user_id) === CURRENT_USER_ID;
        const displayName = mine ? "Vous" : (message.username || "Utilisateur");
        const row = document.createElement("div");
        row.className = `chat-row ${mine ? "me" : "them"}`;

        const avatar = document.createElement("div");
        avatar.className = "chat-avatar";
        avatar.textContent = mine ? "VO" : getInitials(message.username);

        const body = document.createElement("div");
        body.className = "chat-row-body";

        const bubble = document.createElement("div");
        bubble.className = `chat-bubble ${mine ? "me" : "them"}`;

        const meta = document.createElement("div");
        meta.className = "chat-meta";
        meta.innerHTML = `
            <span class="chat-user-wrap">
                <span class="chat-user">${escapeHTML(displayName)}</span>
                <span class="chat-user-role">${escapeHTML(formatRoleLabel(message.user_role, message.user_role_label))}</span>
            </span>
            <span class="chat-time">${escapeHTML(formatTime(message.created_at))}</span>
        `;

        const scope = document.createElement("div");
        scope.className = "chat-scope";
        scope.textContent = buildMessageScopeLabel(message, mine);

        bubble.appendChild(meta);
        bubble.appendChild(scope);

        if (message.message) {
            const text = document.createElement("div");
            text.className = "chat-text";
            text.textContent = message.message;
            bubble.appendChild(text);
        }

        if (message.file_url) {
            const fileLink = document.createElement("a");
            fileLink.className = "chat-file";
            fileLink.href = message.file_url;
            fileLink.target = "_blank";
            fileLink.rel = "noopener";
            fileLink.textContent = `Ouvrir: ${message.file_name || "fichier"}`;
            bubble.appendChild(fileLink);
        }

        if (mine) {
            const status = document.createElement("div");
            status.className = "chat-status";

            if ((message.scope || "broadcast") === "direct") {
                status.innerHTML = message.is_read
                    ? '<span class="chat-read read">Lu</span>'
                    : '<span class="chat-read sent">Envoye</span>';
                bubble.appendChild(status);
            }
        }

        body.appendChild(bubble);

        if (mine) {
            row.appendChild(body);
            row.appendChild(avatar);
        } else {
            row.appendChild(avatar);
            row.appendChild(body);
        }

        return row;
    }

    function renderMessages(messages) {
        if (!Array.isArray(messages) || messages.length === 0) {
            renderEmptyState();
            return;
        }

        const fragment = document.createDocumentFragment();
        let previousDay = null;

        messages.forEach((message) => {
            const currentDay = formatDayLabel(message.created_at);

            if (currentDay && currentDay !== previousDay) {
                const divider = document.createElement("div");
                divider.className = "chat-day-divider";
                divider.innerHTML = `<span>${escapeHTML(currentDay)}</span>`;
                fragment.appendChild(divider);
                previousDay = currentDay;
            }

            fragment.appendChild(renderMessage(message));
        });

        messagesBox.innerHTML = "";
        messagesBox.appendChild(fragment);
    }

    function getLatestMessageId(messages) {
        if (!Array.isArray(messages) || messages.length === 0) {
            return null;
        }

        return messages.reduce((maxId, message) => {
            const currentId = normalizeId(message.id);

            if (currentId === null) {
                return maxId;
            }

            if (maxId === null || currentId > maxId) {
                return currentId;
            }

            return maxId;
        }, null);
    }

    function computeSignature(messages) {
        if (!Array.isArray(messages) || messages.length === 0) {
            return "";
        }

        return messages
            .map((message) => {
                const scope = message.scope || "broadcast";
                return [
                    message.id,
                    message.is_read ? 1 : 0,
                    scope,
                    message.recipient_id || 0,
                    message.file_key || "",
                    message.message || "",
                ].join(":");
            })
            .join("|");
    }

    function hasNewIncomingMessages(messages) {
        if (!Array.isArray(messages) || messages.length === 0) {
            return false;
        }

        if (state.lastMessageId === null) {
            return false;
        }

        return messages.some((message) => {
            const messageId = normalizeId(message.id);
            const senderId = normalizeId(message.user_id);

            return (
                messageId !== null &&
                messageId > state.lastMessageId &&
                senderId !== null &&
                senderId !== CURRENT_USER_ID
            );
        });
    }

    async function loadBootstrap() {
        if (state.isBootstrapLoaded) {
            return;
        }

        try {
            const response = await fetch("/chat/bootstrap", {
                credentials: "same-origin",
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const data = await parseJSONResponse(response, "Impossible de charger les destinataires du chat.");
            populateRecipients(data.recipients || []);
            state.currentUser = data.current_user || null;
            state.isBootstrapLoaded = true;
        } catch (error) {
            console.error("Erreur bootstrap chat", error);
        }
    }

    async function markAsRead() {
        try {
            const headers = {};

            if (CSRF_TOKEN) {
                headers["X-CSRF-Token"] = CSRF_TOKEN;
            }

            await fetch("/chat/mark_read", {
                method: "POST",
                credentials: "same-origin",
                headers,
            });
        } catch (error) {
            console.error("Erreur mark_read", error);
        }
    }

    async function loadMessages(forceScroll = false) {
        if (state.isLoading) {
            return;
        }

        state.isLoading = true;

        try {
            await loadBootstrap();

            const response = await fetch("/chat/messages?limit=120", {
                credentials: "same-origin",
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const data = await parseJSONResponse(response, "Impossible de charger les messages du chat.");
            const messages = Array.isArray(data.messages) ? data.messages : [];
            const signature = computeSignature(messages);

            if (!state.isFirstLoad && hasNewIncomingMessages(messages)) {
                playReceiveSound();
            }

            if (signature !== state.lastRenderedSignature) {
                renderMessages(messages);
                state.lastRenderedSignature = signature;

                if (forceScroll || isOpen()) {
                    scrollBottom();
                }
            }

            const unreadCount = Number(data.unread_count || 0);

            if (!isOpen()) {
                setBadge(unreadCount);
            } else {
                setBadge(0);
            }

            const latestMessageId = getLatestMessageId(messages);

            if (latestMessageId !== null) {
                state.lastMessageId = latestMessageId;
            }

            if (state.isFirstLoad) {
                state.isFirstLoad = false;
            }
        } catch (error) {
            console.error("Erreur chargement chat", error);
        } finally {
            state.isLoading = false;
        }
    }

    function setSendingState(isSending) {
        state.isSending = isSending;
        input.disabled = isSending;
        recipientSelect.disabled = isSending;

        if (sendBtn) {
            sendBtn.disabled = isSending;
        }

        if (fileInput) {
            fileInput.disabled = isSending;
        }

        if (refreshBtn) {
            refreshBtn.disabled = isSending;
        }
    }

    async function sendMessage() {
        if (state.isSending) {
            return;
        }

        const message = input.value.trim();
        const files = fileInput && fileInput.files ? Array.from(fileInput.files) : [];

        if (!message && files.length === 0) {
            return;
        }

        if (files.length > 0 && !CAN_UPLOAD) {
            window.alert("Vous n'etes pas autorise a envoyer des fichiers.");
            return;
        }

        const formData = new FormData();

        if (message) {
            formData.append("message", message);
        }

        if (recipientSelect.value && recipientSelect.value !== "all") {
            formData.append("recipient_id", recipientSelect.value);
        }

        files.forEach((file) => {
            formData.append("file", file);
        });

        const headers = {};

        if (CSRF_TOKEN) {
            headers["X-CSRF-Token"] = CSRF_TOKEN;
        }

        setSendingState(true);

        try {
            const response = await fetch("/chat/send", {
                method: "POST",
                body: formData,
                credentials: "same-origin",
                headers,
            });

            const data = await parseJSONResponse(response, "Erreur lors de l'envoi du message.");

            if (!response.ok || !data.success) {
                throw new Error(data.message || `HTTP ${response.status}`);
            }

            input.value = "";

            if (fileInput) {
                fileInput.value = "";
            }

            updateFilePreview();
            autoResizeInput();
            playSendSound();

            await loadMessages(true);

            if (isOpen()) {
                await markAsRead();
            }
        } catch (error) {
            console.error("Erreur envoi chat", error);
            window.alert(error.message || "Erreur lors de l'envoi du message.");
        } finally {
            setSendingState(false);
            input.focus();
        }
    }

    function schedulePoll() {
        if (state.pollTimer) {
            window.clearTimeout(state.pollTimer);
        }

        let delay = 7000;

        if (document.visibilityState === "hidden") {
            delay = 12000;
        } else if (isOpen()) {
            delay = 3500;
        }

        state.pollTimer = window.setTimeout(async () => {
            await loadMessages(false);

            if (isOpen()) {
                await markAsRead();
            }

            schedulePoll();
        }, delay);
    }

    function openChat() {
        widget.classList.add("open");
        widget.setAttribute("aria-hidden", "false");
        toggleBtn.setAttribute("aria-expanded", "true");
        setBadge(0);

        loadBootstrap()
            .then(() => loadMessages(true))
            .then(() => markAsRead())
            .finally(() => {
                window.setTimeout(() => input.focus(), 80);
                schedulePoll();
            });
    }

    function closeChat() {
        widget.classList.remove("open");
        widget.setAttribute("aria-hidden", "true");
        toggleBtn.setAttribute("aria-expanded", "false");
        schedulePoll();
    }

    toggleBtn.addEventListener("click", () => {
        unlockAudio();

        if (isOpen()) {
            closeChat();
        } else {
            openChat();
        }
    });

    if (closeBtn) {
        closeBtn.addEventListener("click", closeChat);
    }

    if (refreshBtn) {
        refreshBtn.addEventListener("click", async () => {
            await loadMessages(true);

            if (isOpen()) {
                await markAsRead();
            }
        });
    }

    recipientSelect.addEventListener("change", () => {
        saveRecipientSelection(recipientSelect.value || "all");
        updateContextBanner();
        renderQuickRecipients();
    });

    fileInput.addEventListener("change", updateFilePreview);

    form.addEventListener("submit", (event) => {
        event.preventDefault();
        unlockAudio();
        sendMessage();
    });

    input.addEventListener("keydown", (event) => {
        if (event.key === "Enter" && !event.shiftKey) {
            event.preventDefault();
            unlockAudio();
            sendMessage();
        }
    });

    input.addEventListener("input", autoResizeInput);
    document.addEventListener("click", unlockAudio, { passive: true });
    document.addEventListener("keydown", unlockAudio);
    window.addEventListener("focus", () => {
        unlockAudio();
        loadMessages(false);
    });

    document.addEventListener("visibilitychange", () => {
        schedulePoll();
    });

    autoResizeInput();
    updateContextBanner();
    updateFilePreview();
    loadBootstrap().finally(() => loadMessages(false));
    schedulePoll();
});
