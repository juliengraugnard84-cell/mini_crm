document.addEventListener("DOMContentLoaded", function () {

    const calendarEl = document.getElementById("calendar");

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

        // ✅ FIX COMPLET : parsing propre des events
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
                date: e.startStr.slice(0, 10),
                start_time: e.startStr.slice(11, 16),
                end_time: e.endStr ? e.endStr.slice(11, 16) : "10:00"
            });
        }
    });

    calendar.render();

    /* ==========================
       MODALE
    ========================== */

    function openModal(data) {
        document.getElementById("rdv-id").value = data.id || "";
        document.getElementById("rdv-title").value = data.title || "";
        document.getElementById("rdv-date").value = data.date || "";
        document.getElementById("rdv-start").value = data.start_time || "09:00";
        document.getElementById("rdv-end").value = data.end_time || "10:00";

        document.getElementById("btn-delete").style.display = data.id ? "inline-block" : "none";

        new bootstrap.Modal(document.getElementById("rdvModal")).show();
    }

    /* ==========================
       SAVE
    ========================== */
    document.getElementById("btn-save").addEventListener("click", () => {
        const id = document.getElementById("rdv-id").value;
        const payload = {
            title: document.getElementById("rdv-title").value,
            date: document.getElementById("rdv-date").value,
            start_time: document.getElementById("rdv-start").value,
            end_time: document.getElementById("rdv-end").value
        };

        const url = id ? "/appointments/update" : "/appointments/create";
        if (id) payload.id = id;

        fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        }).then(() => location.reload());
    });

    /* ==========================
       DELETE
    ========================== */
    document.getElementById("btn-delete").addEventListener("click", () => {
        const id = document.getElementById("rdv-id").value;
        if (!confirm("Supprimer ce rendez-vous ?")) return;

        fetch("/appointments/delete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ id })
        }).then(() => location.reload());
    });

});