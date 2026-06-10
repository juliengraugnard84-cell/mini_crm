document.addEventListener("DOMContentLoaded", () => {
    const bootstrapData = window.PLANNING_BOOTSTRAP || {};
    const csrfToken = window.PLANNING_CSRF_TOKEN || "";
    const currentUser = bootstrapData.current_user || {};

    const calendarEl = document.getElementById("planning-calendar");
    const modalEl = document.getElementById("planningEventModal");

    if (!calendarEl || !modalEl || typeof FullCalendar === "undefined") {
        return;
    }

    const nodes = {
        feedback: document.getElementById("planning-feedback"),
        statToday: document.getElementById("planning-stat-today"),
        statWeek: document.getElementById("planning-stat-week"),
        statNegotiations: document.getElementById("planning-stat-negociations"),
        statTeam: document.getElementById("planning-stat-team"),
        search: document.getElementById("planning-search"),
        userFilter: document.getElementById("planning-user-filter"),
        statusFilter: document.getElementById("planning-status-filter"),
        mineOnly: document.getElementById("planning-mine-only"),
        weekends: document.getElementById("planning-weekends"),
        showCancelled: document.getElementById("planning-show-cancelled"),
        sourcePills: Array.from(document.querySelectorAll(".planning-source-pill")),
        upcoming: document.getElementById("planning-upcoming"),
        upcomingEmpty: document.getElementById("planning-upcoming-empty"),
        createButton: document.getElementById("planning-create-button"),
        resetFiltersButton: document.getElementById("planning-reset-filters"),
        modalKicker: document.getElementById("planning-modal-kicker"),
        modalTitle: document.getElementById("planning-modal-title"),
        readOnlyNote: document.getElementById("planning-readonly-note"),
        eventId: document.getElementById("planning-event-id"),
        eventSource: document.getElementById("planning-event-source"),
        form: document.getElementById("planning-event-form"),
        title: document.getElementById("planning-event-title"),
        category: document.getElementById("planning-event-category"),
        status: document.getElementById("planning-event-status"),
        visibility: document.getElementById("planning-event-visibility"),
        assignee: document.getElementById("planning-event-assignee"),
        startDate: document.getElementById("planning-start-date"),
        endDate: document.getElementById("planning-end-date"),
        startTime: document.getElementById("planning-start-time"),
        endTime: document.getElementById("planning-end-time"),
        location: document.getElementById("planning-event-location"),
        color: document.getElementById("planning-event-color"),
        allDay: document.getElementById("planning-all-day"),
        description: document.getElementById("planning-event-description"),
        openLink: document.getElementById("planning-open-link"),
        deleteButton: document.getElementById("planning-delete-button"),
        saveButton: document.getElementById("planning-save-button"),
    };

    const state = {
        activeSources: new Set(["cotation", "update", "manual"]),
        calendar: null,
        modal: new bootstrap.Modal(modalEl),
        rawEvents: [],
        searchTimer: null,
        saving: false,
    };

    const dateFormatter = new Intl.DateTimeFormat("fr-FR", {
        weekday: "short",
        day: "2-digit",
        month: "short",
    });

    const dateTimeFormatter = new Intl.DateTimeFormat("fr-FR", {
        day: "2-digit",
        month: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
    });

    function escapeHTML(value) {
        return String(value || "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;");
    }

    function parseDateLike(value) {
        if (!value) {
            return null;
        }

        if (/^\d{4}-\d{2}-\d{2}$/.test(value)) {
            const [year, month, day] = value.split("-").map(Number);
            return new Date(year, month - 1, day, 12, 0, 0, 0);
        }

        const parsed = new Date(value);
        return Number.isNaN(parsed.getTime()) ? null : parsed;
    }

    function cloneDate(value) {
        return new Date(value.getTime());
    }

    function startOfDay(value) {
        const copy = cloneDate(value);
        copy.setHours(0, 0, 0, 0);
        return copy;
    }

    function addDays(value, amount) {
        const copy = cloneDate(value);
        copy.setDate(copy.getDate() + amount);
        return copy;
    }

    function sameDay(a, b) {
        return a.getFullYear() === b.getFullYear()
            && a.getMonth() === b.getMonth()
            && a.getDate() === b.getDate();
    }

    function formatDateInput(value) {
        const year = value.getFullYear();
        const month = String(value.getMonth() + 1).padStart(2, "0");
        const day = String(value.getDate()).padStart(2, "0");
        return `${year}-${month}-${day}`;
    }

    function formatTimeInput(value) {
        const hours = String(value.getHours()).padStart(2, "0");
        const minutes = String(value.getMinutes()).padStart(2, "0");
        return `${hours}:${minutes}`;
    }

    function extractEventDateFields(start, end, allDay) {
        if (!start) {
            return {
                startDate: "",
                endDate: "",
                startTime: "",
                endTime: "",
                allDay: Boolean(allDay),
            };
        }

        const payload = {
            startDate: formatDateInput(start),
            endDate: formatDateInput(start),
            startTime: "",
            endTime: "",
            allDay: Boolean(allDay),
        };

        if (allDay) {
            if (end && end > start) {
                payload.endDate = formatDateInput(addDays(end, -1));
            }
            return payload;
        }

        payload.startTime = formatTimeInput(start);

        if (end) {
            payload.endDate = formatDateInput(end);
            payload.endTime = formatTimeInput(end);
        }

        return payload;
    }

    function buildReadableSchedule(eventLike) {
        if (!eventLike) {
            return "";
        }

        const start = eventLike.start instanceof Date
            ? eventLike.start
            : parseDateLike(eventLike.start);
        const end = eventLike.end instanceof Date
            ? eventLike.end
            : parseDateLike(eventLike.end);
        const allDay = Boolean(eventLike.allDay);

        if (!start) {
            return "";
        }

        if (allDay) {
            if (end && !sameDay(start, addDays(end, -1))) {
                return `${dateFormatter.format(start)} au ${dateFormatter.format(addDays(end, -1))}`;
            }
            return `Journee entiere - ${dateFormatter.format(start)}`;
        }

        if (end) {
            return `${dateTimeFormatter.format(start)} - ${dateTimeFormatter.format(end)}`;
        }

        return dateTimeFormatter.format(start);
    }

    function sourceBadgeClass(sourceKind) {
        return `planning-badge-${sourceKind || "manual"}`;
    }

    function showFeedback(kind, message) {
        if (!nodes.feedback) {
            return;
        }

        nodes.feedback.hidden = false;
        nodes.feedback.className = `planning-feedback planning-feedback-${kind}`;
        nodes.feedback.textContent = message;

        window.clearTimeout(nodes.feedback._timer);
        nodes.feedback._timer = window.setTimeout(() => {
            nodes.feedback.hidden = true;
        }, 3200);
    }

    function getSourceKind(eventLike) {
        return eventLike.extendedProps?.sourceKind || "manual";
    }

    function matchesUserFilter(eventLike, selectedUserId) {
        if (selectedUserId === "all") {
            return true;
        }

        const props = eventLike.extendedProps || {};
        const candidateIds = [
            props.ownerUserId,
            props.assignedToId,
            props.createdById,
        ].filter(Boolean).map(String);

        return candidateIds.includes(String(selectedUserId));
    }

    function matchesMineOnly(eventLike) {
        if (!nodes.mineOnly.checked) {
            return true;
        }

        const props = eventLike.extendedProps || {};
        const currentId = String(currentUser.id || "");
        const candidateIds = [
            props.ownerUserId,
            props.assignedToId,
            props.createdById,
        ].filter(Boolean).map(String);

        return candidateIds.includes(currentId);
    }

    function matchesSearch(eventLike, query) {
        if (!query) {
            return true;
        }

        const props = eventLike.extendedProps || {};
        const haystack = [
            eventLike.title,
            props.description,
            props.location,
            props.clientName,
            props.commercialName,
            props.ownerLabel,
            props.sourceLabel,
            props.visibilityLabel,
        ].join(" ").toLowerCase();

        return haystack.includes(query);
    }

    function applyFilters(events) {
        const query = (nodes.search.value || "").trim().toLowerCase();
        const selectedUserId = nodes.userFilter.value || "all";
        const selectedStatus = nodes.statusFilter.value || "all";
        const showCancelled = nodes.showCancelled.checked;

        return events.filter((eventLike) => {
            const props = eventLike.extendedProps || {};
            const sourceKind = getSourceKind(eventLike);
            const status = props.status || "confirmed";

            if (!state.activeSources.has(sourceKind)) {
                return false;
            }

            if (!showCancelled && status === "cancelled") {
                return false;
            }

            if (selectedStatus !== "all" && status !== selectedStatus) {
                return false;
            }

            if (!matchesUserFilter(eventLike, selectedUserId)) {
                return false;
            }

            if (!matchesMineOnly(eventLike)) {
                return false;
            }

            return matchesSearch(eventLike, query);
        });
    }

    function renderStats(events) {
        const today = startOfDay(new Date());
        const weekBoundary = addDays(today, 7);

        let todayCount = 0;
        let weekCount = 0;
        let negotiationCount = 0;
        let teamCount = 0;

        events.forEach((eventLike) => {
            const start = parseDateLike(eventLike.start);
            const sourceKind = getSourceKind(eventLike);
            const props = eventLike.extendedProps || {};

            if (sourceKind === "cotation") {
                negotiationCount += 1;
            }

            if (sourceKind === "manual" && ["team", "assigned"].includes(props.visibility)) {
                teamCount += 1;
            }

            if (!start) {
                return;
            }

            const eventDay = startOfDay(start);

            if (sameDay(eventDay, today)) {
                todayCount += 1;
            }

            if (eventDay >= today && eventDay < weekBoundary) {
                weekCount += 1;
            }
        });

        nodes.statToday.textContent = String(todayCount);
        nodes.statWeek.textContent = String(weekCount);
        nodes.statNegotiations.textContent = String(negotiationCount);
        nodes.statTeam.textContent = String(teamCount);
    }

    function renderUpcoming(events) {
        const now = new Date();
        const sorted = events
            .map((eventLike) => ({
                event: eventLike,
                date: parseDateLike(eventLike.start),
            }))
            .filter((entry) => entry.date && entry.date >= addDays(startOfDay(now), -1))
            .sort((a, b) => a.date - b.date)
            .slice(0, 8);

        if (!sorted.length) {
            nodes.upcoming.innerHTML = "";
            nodes.upcomingEmpty.style.display = "block";
            return;
        }

        nodes.upcomingEmpty.style.display = "none";
        nodes.upcoming.innerHTML = sorted.map(({ event, date }) => {
            const props = event.extendedProps || {};
            const owner = props.ownerLabel || props.createdByName || props.commercialName || "Equipe";
            const location = props.location ? `<span>${escapeHTML(props.location)}</span>` : "";
            const displayTitle = props.titleFull || event.title || "";

            return `
                <article class="planning-upcoming-item">
                    <div class="planning-upcoming-day">${escapeHTML(dateFormatter.format(date))}</div>
                    <div class="planning-upcoming-body">
                        <div class="planning-upcoming-top">
                            <span class="planning-inline-badge ${sourceBadgeClass(props.sourceKind)}">${escapeHTML(props.sourceLabel || "Agenda")}</span>
                            <span class="planning-upcoming-owner">${escapeHTML(owner)}</span>
                        </div>
                        <strong>${escapeHTML(displayTitle)}</strong>
                        <div class="planning-upcoming-meta">
                            <span>${escapeHTML(buildReadableSchedule({ start: date, end: parseDateLike(event.end), allDay: event.allDay }))}</span>
                            ${location}
                        </div>
                    </div>
                </article>
            `;
        }).join("");
    }

    function renderInsights(events) {
        renderStats(events);
        renderUpcoming(events);
    }

    async function fetchPlanningEvents(fetchInfo, successCallback, failureCallback) {
        const params = new URLSearchParams({
            start: fetchInfo.startStr,
            end: fetchInfo.endStr,
        });

        try {
            const response = await fetch(`/api/planning/events?${params.toString()}`, {
                headers: {
                    "Accept": "application/json",
                },
            });

            const payload = await response.json();

            if (!response.ok || payload.success === false) {
                throw new Error(payload.message || "Chargement impossible.");
            }

            state.rawEvents = Array.isArray(payload.events) ? payload.events : [];
            const filtered = applyFilters(state.rawEvents);
            renderInsights(filtered);
            successCallback(filtered);
        } catch (error) {
            console.error("Erreur chargement agenda:", error);
            showFeedback("danger", "Impossible de charger l'agenda.");
            failureCallback(error);
        }
    }

    function serializeCalendarEvent(event) {
        const props = event.extendedProps || {};
        const dateFields = extractEventDateFields(event.start, event.end, event.allDay);

        return {
            title: event.title || "",
            description: props.description || "",
            location: props.location || "",
            category: props.category || "meeting",
            status: props.status || "confirmed",
            visibility: props.visibility || "private",
            assigned_to: props.assignedToId || "",
            color: props.color || "#2563eb",
            start_date: dateFields.startDate,
            end_date: dateFields.endDate,
            start_time: dateFields.startTime,
            end_time: dateFields.endTime,
            all_day: dateFields.allDay,
        };
    }

    function setModalReadOnly(readOnly) {
        const fields = [
            nodes.title,
            nodes.category,
            nodes.status,
            nodes.visibility,
            nodes.assignee,
            nodes.startDate,
            nodes.endDate,
            nodes.startTime,
            nodes.endTime,
            nodes.location,
            nodes.color,
            nodes.allDay,
            nodes.description,
        ];

        fields.forEach((field) => {
            field.disabled = readOnly;
        });

        nodes.saveButton.classList.toggle("d-none", readOnly);
        nodes.deleteButton.classList.toggle("d-none", readOnly);
        nodes.readOnlyNote.classList.toggle("d-none", !readOnly);
    }

    function syncAllDayFields() {
        const disabled = nodes.allDay.checked;
        nodes.startTime.disabled = disabled;
        nodes.endTime.disabled = disabled;

        if (disabled) {
            nodes.startTime.value = "";
            nodes.endTime.value = "";
        }
    }

    function syncVisibilityFields() {
        const visibility = nodes.visibility.value;
        const privateEvent = visibility === "private";

        nodes.assignee.disabled = privateEvent;

        if (privateEvent) {
            nodes.assignee.value = String(currentUser.id || "");
        }
    }

    function resetModalForm() {
        nodes.form.reset();
        nodes.eventId.value = "";
        nodes.eventSource.value = "manual";
        nodes.category.value = "meeting";
        nodes.status.value = "confirmed";
        nodes.visibility.value = "private";
        nodes.assignee.value = String(currentUser.id || "");
        nodes.color.value = "#2563eb";
        nodes.openLink.classList.add("d-none");
        nodes.openLink.removeAttribute("href");
        nodes.deleteButton.classList.add("d-none");
        syncAllDayFields();
        syncVisibilityFields();
        setModalReadOnly(false);
    }

    function openCreateModalFromSelection(selection = null) {
        resetModalForm();

        const baseStart = selection?.start || new Date();
        const baseEnd = selection?.end || addDays(baseStart, 0);
        const allDay = Boolean(selection?.allDay);
        const dateFields = extractEventDateFields(baseStart, baseEnd, allDay);

        nodes.modalKicker.textContent = "Nouveau rendez-vous";
        nodes.modalTitle.textContent = "Creer un bloc agenda";
        nodes.startDate.value = dateFields.startDate || formatDateInput(new Date());
        nodes.endDate.value = dateFields.endDate || nodes.startDate.value;
        nodes.startTime.value = allDay ? "" : (dateFields.startTime || "09:00");
        nodes.endTime.value = allDay ? "" : (dateFields.endTime || "10:00");
        nodes.allDay.checked = allDay;

        syncAllDayFields();
        syncVisibilityFields();
        state.modal.show();
    }

    function fillModalFromEvent(event) {
        resetModalForm();

        const props = event.extendedProps || {};
        const dateFields = extractEventDateFields(event.start, event.end, event.allDay);
        const readOnly = !props.canEdit || props.sourceKind !== "manual";

        nodes.eventId.value = String(props.entityId || "");
        nodes.eventSource.value = props.sourceKind || "manual";
        nodes.title.value = event.title || "";
        nodes.category.value = props.category || "meeting";
        nodes.status.value = props.status || "confirmed";
        nodes.visibility.value = props.visibility || "private";
        nodes.assignee.value = props.assignedToId ? String(props.assignedToId) : "";
        nodes.startDate.value = dateFields.startDate;
        nodes.endDate.value = dateFields.endDate;
        nodes.startTime.value = dateFields.startTime || "";
        nodes.endTime.value = dateFields.endTime || "";
        nodes.location.value = props.location || "";
        nodes.color.value = props.color || "#2563eb";
        nodes.allDay.checked = Boolean(event.allDay);
        nodes.description.value = props.description || "";

        nodes.modalKicker.textContent = props.sourceLabel || "Agenda";
        nodes.modalTitle.textContent = props.titleFull || event.title || "Rendez-vous";

        if (props.routeUrl) {
            nodes.openLink.href = props.routeUrl;
            nodes.openLink.classList.remove("d-none");
        }

        if (!readOnly && props.canDelete) {
            nodes.deleteButton.classList.remove("d-none");
        }

        setModalReadOnly(readOnly);
        syncAllDayFields();
        syncVisibilityFields();
        state.modal.show();
    }

    function collectFormPayload() {
        const title = nodes.title.value.trim();
        const startDate = nodes.startDate.value;
        const endDate = nodes.endDate.value || startDate;

        if (!title) {
            showFeedback("warning", "Le titre du rendez-vous est obligatoire.");
            nodes.title.focus();
            return null;
        }

        if (!startDate) {
            showFeedback("warning", "Choisis une date de debut.");
            nodes.startDate.focus();
            return null;
        }

        return {
            title,
            description: nodes.description.value.trim(),
            location: nodes.location.value.trim(),
            category: nodes.category.value,
            status: nodes.status.value,
            visibility: nodes.visibility.value,
            assigned_to: nodes.assignee.value,
            color: nodes.color.value,
            start_date: startDate,
            end_date: endDate,
            start_time: nodes.allDay.checked ? "" : (nodes.startTime.value || "09:00"),
            end_time: nodes.allDay.checked ? "" : nodes.endTime.value,
            all_day: nodes.allDay.checked,
        };
    }

    async function postJSON(url, body) {
        const response = await fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-CSRF-Token": csrfToken,
            },
            body: JSON.stringify(body),
        });

        const payload = await response.json();

        if (!response.ok || payload.success === false) {
            throw new Error(payload.message || "Erreur serveur.");
        }

        return payload;
    }

    async function saveModalEvent(event) {
        event.preventDefault();

        if (state.saving) {
            return;
        }

        const sourceKind = nodes.eventSource.value || "manual";
        if (sourceKind !== "manual") {
            state.modal.hide();
            return;
        }

        const payload = collectFormPayload();
        if (!payload) {
            return;
        }

        state.saving = true;
        nodes.saveButton.disabled = true;

        try {
            const entityId = nodes.eventId.value;
            const url = entityId
                ? `/api/planning/events/${entityId}/update`
                : "/api/planning/events";

            await postJSON(url, payload);
            state.modal.hide();
            state.calendar.refetchEvents();
            showFeedback("success", entityId ? "Rendez-vous mis a jour." : "Rendez-vous cree.");
        } catch (error) {
            console.error("Erreur sauvegarde agenda:", error);
            showFeedback("danger", error.message || "Impossible d'enregistrer le rendez-vous.");
        } finally {
            state.saving = false;
            nodes.saveButton.disabled = false;
        }
    }

    async function deleteCurrentEvent() {
        const entityId = nodes.eventId.value;

        if (!entityId || !window.confirm("Supprimer ce rendez-vous ?")) {
            return;
        }

        try {
            await postJSON(`/api/planning/events/${entityId}/delete`, {});
            state.modal.hide();
            state.calendar.refetchEvents();
            showFeedback("success", "Rendez-vous supprime.");
        } catch (error) {
            console.error("Erreur suppression agenda:", error);
            showFeedback("danger", error.message || "Suppression impossible.");
        }
    }

    async function persistEventMove(info) {
        const props = info.event.extendedProps || {};

        if (props.sourceKind !== "manual" || !props.canEdit) {
            info.revert();
            return;
        }

        try {
            await postJSON(
                `/api/planning/events/${props.entityId}/update`,
                serializeCalendarEvent(info.event)
            );
            state.calendar.refetchEvents();
            showFeedback("success", "Rendez-vous reprogramme.");
        } catch (error) {
            console.error("Erreur deplacement agenda:", error);
            info.revert();
            showFeedback("danger", error.message || "Impossible de reprogrammer ce rendez-vous.");
        }
    }

    function updateSourcePills() {
        nodes.sourcePills.forEach((button) => {
            const source = button.dataset.source;
            button.classList.toggle("is-active", state.activeSources.has(source));
        });
    }

    function refreshCalendarFilters() {
        renderInsights(applyFilters(state.rawEvents));
        state.calendar.refetchEvents();
    }

    function bindFilters() {
        nodes.sourcePills.forEach((button) => {
            button.addEventListener("click", () => {
                const source = button.dataset.source;

                if (state.activeSources.has(source) && state.activeSources.size > 1) {
                    state.activeSources.delete(source);
                } else {
                    state.activeSources.add(source);
                }

                updateSourcePills();
                refreshCalendarFilters();
            });
        });

        [nodes.userFilter, nodes.statusFilter, nodes.mineOnly, nodes.showCancelled].forEach((node) => {
            node.addEventListener("change", refreshCalendarFilters);
        });

        nodes.weekends.addEventListener("change", () => {
            state.calendar.setOption("weekends", nodes.weekends.checked);
        });

        nodes.search.addEventListener("input", () => {
            window.clearTimeout(state.searchTimer);
            state.searchTimer = window.setTimeout(refreshCalendarFilters, 180);
        });

        nodes.resetFiltersButton.addEventListener("click", () => {
            nodes.search.value = "";
            nodes.userFilter.value = "all";
            nodes.statusFilter.value = "all";
            nodes.mineOnly.checked = false;
            nodes.showCancelled.checked = true;
            nodes.weekends.checked = true;
            state.activeSources = new Set(["cotation", "update", "manual"]);
            updateSourcePills();
            state.calendar.setOption("weekends", true);
            refreshCalendarFilters();
        });
    }

    function bindModalControls() {
        nodes.form.addEventListener("submit", saveModalEvent);
        nodes.createButton.addEventListener("click", () => openCreateModalFromSelection());
        nodes.deleteButton.addEventListener("click", deleteCurrentEvent);
        nodes.allDay.addEventListener("change", syncAllDayFields);
        nodes.visibility.addEventListener("change", syncVisibilityFields);
    }

    function initCalendar() {
        state.calendar = new FullCalendar.Calendar(calendarEl, {
            locale: "fr",
            firstDay: 1,
            initialView: "timeGridWeek",
            nowIndicator: true,
            navLinks: true,
            selectable: true,
            selectMirror: true,
            editable: true,
            eventResizableFromStart: true,
            slotEventOverlap: false,
            dayMaxEvents: true,
            height: "auto",
            expandRows: true,
            stickyHeaderDates: true,
            scrollTime: "08:00:00",
            slotMinTime: "07:00:00",
            slotMaxTime: "21:00:00",
            weekends: true,
            businessHours: {
                daysOfWeek: [1, 2, 3, 4, 5],
                startTime: "08:00",
                endTime: "19:00",
            },
            headerToolbar: {
                left: "prev,next today",
                center: "title",
                right: "dayGridMonth,timeGridWeek,timeGridDay,listWeek",
            },
            buttonText: {
                today: "Aujourd'hui",
                month: "Mois",
                week: "Semaine",
                day: "Jour",
                list: "Liste",
            },
            views: {
                timeGridWeek: {
                    dayHeaderFormat: { weekday: "long", day: "numeric", month: "short" },
                },
                timeGridDay: {
                    dayHeaderFormat: { weekday: "long", day: "numeric", month: "long" },
                },
                listWeek: {
                    noEventsContent: "Aucun element sur cette periode.",
                },
            },
            eventTimeFormat: {
                hour: "2-digit",
                minute: "2-digit",
                hour12: false,
            },
            events: fetchPlanningEvents,
            select: (info) => {
                let start = info.start;
                let end = info.end;

                if (info.allDay && end) {
                    end = addDays(end, -1);
                }

                openCreateModalFromSelection({
                    start,
                    end,
                    allDay: info.allDay,
                });
            },
            eventClick: (info) => {
                fillModalFromEvent(info.event);
            },
            eventDrop: persistEventMove,
            eventResize: persistEventMove,
            eventDidMount: (info) => {
                const props = info.event.extendedProps || {};
                const lines = [
                    props.sourceLabel || "Agenda",
                    props.titleFull || info.event.title || "",
                    buildReadableSchedule(info.event),
                    props.ownerLabel ? `Responsable : ${props.ownerLabel}` : "",
                    props.location ? `Lieu : ${props.location}` : "",
                ].filter(Boolean);

                info.el.setAttribute("title", lines.join("\n"));
            },
            eventContent: (arg) => {
                const props = arg.event.extendedProps || {};
                const sourceLabel = props.sourceLabel || "Agenda";
                const owner = props.ownerLabel || props.commercialName || "";
                const displayTitle = props.titleFull || arg.event.title || "";
                const status = props.status === "tentative"
                    ? `<span class="planning-event-status">${escapeHTML(props.statusLabel || "Tentatif")}</span>`
                    : "";

                return {
                    html: `
                        <div class="planning-event-card">
                            <div class="planning-event-card-top">
                                <span class="planning-inline-badge ${sourceBadgeClass(props.sourceKind)}">${escapeHTML(sourceLabel)}</span>
                                ${status}
                            </div>
                            <div class="planning-event-card-title">${escapeHTML(displayTitle)}</div>
                            <div class="planning-event-card-meta">
                                <span>${escapeHTML(arg.timeText || (arg.event.allDay ? "Journee" : ""))}</span>
                                ${owner ? `<span>${escapeHTML(owner)}</span>` : ""}
                            </div>
                        </div>
                    `,
                };
            },
        });

        state.calendar.render();
    }

    bindFilters();
    bindModalControls();
    updateSourcePills();
    syncAllDayFields();
    syncVisibilityFields();
    initCalendar();
});
