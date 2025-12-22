document.addEventListener("DOMContentLoaded", function () {

    const calendarEl = document.getElementById("calendar");
    if (!calendarEl) return;

    const calendar = new FullCalendar.Calendar(calendarEl, {
        initialView: "timeGridWeek",
        locale: "fr",
        firstDay: 1,

        selectable: true,
        editable: true,
        eventResizableFromStart: true,

        height: "auto",

        slotMinTime: "07:00:00",
        slotMaxTime: "20:00:00",
        slotDuration: "00:15:00",

        headerToolbar: {
            left: "prev,next today",
            center: "title",
            right: "dayGridMonth,timeGridWeek,timeGridDay"
        },

        events: "/appointments/events_json",

        /* =====================
           CRÉATION RDV
        ===================== */
        select(info) {
            const title = prompt("Titre du rendez-vous");
            if (!title) {
                calendar.unselect();
                return;
            }

            fetch("/appointments/create", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    title: title,
                    date: info.startStr.slice(0, 10),
                    start_time: info.startStr.slice(11, 16),
                    end_time: info.endStr.slice(11, 16)
                })
            })
            .then(r => r.json())
            .then(() => calendar.refetchEvents())
            .catch(() => alert("Erreur création RDV"));

            calendar.unselect();
        },

        /* =====================
           DRAG & RESIZE
        ===================== */
        eventDrop: persistEvent,
        eventResize: persistEvent,

        /* =====================
           CLIC : MODIFIER / SUPPRIMER
        ===================== */
        eventClick(info) {
            const e = info.event;

            const action = prompt(
                "Modifier le titre ou taper SUPPRIMER pour supprimer",
                e.title
            );

            if (!action) return;

            /* ===== SUPPRESSION ===== */
            if (action.toLowerCase() === "supprimer") {
                if (!confirm("Confirmer la suppression du rendez-vous ?")) return;

                fetch(`/appointments/${e.id}/delete`, {
                    method: "POST"
                })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        e.remove();
                    } else {
                        alert(data.message || "Erreur suppression");
                    }
                })
                .catch(() => alert("Erreur suppression"));
                return;
            }

            /* ===== MODIFICATION ===== */
            const start = e.start;
            const end = e.end;

            fetch(`/appointments/${e.id}/update`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    title: action,
                    date: start.toISOString().slice(0, 10),
                    start_time: start.toTimeString().slice(0, 5),
                    end_time: end ? end.toTimeString().slice(0, 5) : null
                })
            })
            .then(r => r.json())
            .then(data => {
                if (!data.success) {
                    alert(data.message || "Erreur modification");
                    calendar.refetchEvents();
                }
            });
        },

        /* =====================
           INFO BULLE
        ===================== */
        eventDidMount(info) {
            const createdBy = info.event.extendedProps.created_by;
            if (createdBy) {
                info.el.title = "Créé par : " + createdBy;
            }
        }
    });

    calendar.render();

    function persistEvent(info) {
        const start = info.event.start;
        const end = info.event.end;

        fetch("/appointments/update_from_calendar", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                id: info.event.id,
                date: start.toISOString().slice(0, 10),
                start_time: start.toTimeString().slice(0, 5),
                end_time: end ? end.toTimeString().slice(0, 5) : null
            })
        })
        .then(res => {
            if (!res.ok) {
                alert("Erreur mise à jour");
                info.revert();
            }
        })
        .catch(() => info.revert());
    }
});
