document.addEventListener("DOMContentLoaded", function () {

    const calendarEl = document.getElementById("calendar");

    if (!calendarEl) {
        console.error("Element #calendar introuvable");
        return;
    }

    const calendar = new FullCalendar.Calendar(calendarEl, {
        initialView: "dayGridMonth",
        locale: "fr",
        selectable: true,
        editable: true,
        firstDay: 1,

        headerToolbar: {
            left: "prev,next today",
            center: "title",
            right: "dayGridMonth,timeGridWeek,timeGridDay"
        },

        // ✅ FETCH API OK
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
                start_time: e.startStr ? e.startStr.slice(11, 16) : "",
                end_time: e.endStr ? e.endStr.slice(11, 16) : "10:00"
            });
        }
    });

    calendar.render();

    /* ==========================
       MODALE (SAFE)
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
            deleteBtn.style.display = data.id ? "inline-block" : "none";
        }

        if (modalEl) {
            new bootstrap.Modal(modalEl).show();
        }
    }

    /* ==========================
       SAVE (SAFE)
    ========================== */

    const btnSave = document.getElementById("btn-save");

    if (btnSave) {
        btnSave.addEventListener("click", () => {

            const idField = document.getElementById("rdv-id");
            const titleField = document.getElementById("rdv-title");
            const dateField = document.getElementById("rdv-date");
            const startField = document.getElementById("rdv-start");
            const endField = document.getElementById("rdv-end");

            const id = idField ? idField.value : null;

            const payload = {
                title: titleField ? titleField.value : "",
                date: dateField ? dateField.value : "",
                start_time: startField ? startField.value : "",
                end_time: endField ? endField.value : ""
            };

            const url = id ? "/appointments/update" : "/appointments/create";
            if (id) payload.id = id;

            fetch(url, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            }).then(() => location.reload());
        });
    }

    /* ==========================
       DELETE (SAFE)
    ========================== */

    const btnDelete = document.getElementById("btn-delete");

    if (btnDelete) {
        btnDelete.addEventListener("click", () => {

            const idField = document.getElementById("rdv-id");
            const id = idField ? idField.value : null;

            if (!id) return;

            if (!confirm("Supprimer ce rendez-vous ?")) return;

            fetch("/appointments/delete", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ id })
            }).then(() => location.reload());
        });
    }

});