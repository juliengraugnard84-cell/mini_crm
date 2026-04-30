document.addEventListener("DOMContentLoaded", function () {

    const calendarEl = document.getElementById("calendar");

    if (!calendarEl) {
        console.error("Element #calendar introuvable");
        return;
    }

    function getCsrfToken() {
        const input = document.querySelector('input[name="csrf_token"]');
        return input ? input.value : "";
    }

    const calendar = new FullCalendar.Calendar(calendarEl, {
        initialView: "dayGridMonth",
        locale: "fr",
        selectable: true,
        editable: false,
        firstDay: 1,
        height: 750,

        headerToolbar: {
            left: "prev,next today",
            center: "title",
            right: "dayGridMonth,timeGridWeek,timeGridDay"
        },

        events: function(fetchInfo, successCallback, failureCallback) {

            fetch("/api/calendar")
                .then(response => response.json())
                .then(data => {

                    console.log("EVENTS:", data);

                    const formattedEvents = data.map(e => ({
                        id: e.id,
                        title: e.title,
                        start: e.start,
                        end: e.end || undefined,
                        allDay: e.allDay || false,
                        color: e.color || "#3788d8"
                    }));

                    successCallback(formattedEvents);
                })
                .catch(error => {
                    console.error("Erreur chargement calendrier:", error);
                    failureCallback(error);
                });
        },

        dateClick(info) {
            openModal({
                date: info.dateStr
            });
        },

        eventClick(info) {
            const e = info.event;

            openModal({
                id: e.id,
                title: e.title,
                date: e.startStr ? e.startStr.slice(0, 10) : "",
                start_time: e.startStr && e.startStr.length > 10 ? e.startStr.slice(11, 16) : "09:00",
                end_time: e.endStr && e.endStr.length > 10 ? e.endStr.slice(11, 16) : "10:00"
            });
        }
    });

    calendar.render();


    /* ==========================
       MODALE
    ========================== */

    function openModal(data) {

        const idField = document.getElementById("rdv-id");
        const titleField = document.getElementById("rdv-title");
        const dateField = document.getElementById("rdv-date");
        const startField = document.getElementById("rdv-start");
        const endField = document.getElementById("rdv-end");
        const deleteBtn = document.getElementById("btn-delete");
        const modalEl = document.getElementById("rdvModal");

        if (idField) idField.value = data.id || "";
        if (titleField) titleField.value = data.title || "";
        if (dateField) dateField.value = data.date || "";
        if (startField) startField.value = data.start_time || "09:00";
        if (endField) endField.value = data.end_time || "10:00";

        if (deleteBtn) {
            deleteBtn.style.display = data.id && data.id.startsWith("event_")
                ? "inline-block"
                : "none";
        }

        if (modalEl) {
            const modal = new bootstrap.Modal(modalEl);
            modal.show();
        }
    }


    /* ==========================
       SAVE RDV
    ========================== */

    const btnSave = document.getElementById("btn-save");

    if (btnSave) {
        btnSave.addEventListener("click", () => {

            const titleField = document.getElementById("rdv-title");
            const dateField = document.getElementById("rdv-date");
            const startField = document.getElementById("rdv-start");
            const endField = document.getElementById("rdv-end");

            const title = titleField ? titleField.value.trim() : "";
            const eventDate = dateField ? dateField.value : "";
            const startTime = startField ? startField.value : "";
            const endTime = endField ? endField.value : "";

            if (!title || !eventDate) {
                alert("Titre et date obligatoires.");
                return;
            }

            const formData = new FormData();
            formData.append("csrf_token", getCsrfToken());
            formData.append("title", title);
            formData.append("event_date", eventDate);
            formData.append("start_time", startTime);
            formData.append("end_time", endTime);
            formData.append("description", "");

            fetch("/calendar/add", {
                method: "POST",
                body: formData
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error("Erreur serveur");
                }
                window.location.reload();
            })
            .catch(error => {
                console.error("Erreur création RDV:", error);
                alert("Erreur lors de l'enregistrement du rendez-vous.");
            });
        });
    }


    /* ==========================
       DELETE RDV ADMIN
    ========================== */

    const btnDelete = document.getElementById("btn-delete");

    if (btnDelete) {
        btnDelete.addEventListener("click", () => {

            const idField = document.getElementById("rdv-id");
            const rawId = idField ? idField.value : "";

            if (!rawId || !rawId.startsWith("event_")) return;

            const eventId = rawId.replace("event_", "");

            if (!confirm("Supprimer ce rendez-vous ?")) return;

            const formData = new FormData();
            formData.append("csrf_token", getCsrfToken());

            fetch("/admin/calendar/" + eventId + "/delete", {
                method: "POST",
                body: formData
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error("Suppression refusée ou impossible");
                }
                window.location.reload();
            })
            .catch(error => {
                console.error("Erreur suppression RDV:", error);
                alert("Suppression impossible.");
            });
        });
    }

});