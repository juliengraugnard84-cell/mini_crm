document.addEventListener("DOMContentLoaded", function () {

    const calendarEl = document.getElementById("calendar");
    if (!calendarEl) return;

    const calendar = new FullCalendar.Calendar(calendarEl, {
        locale: "fr",
        firstDay: 1,

        initialView: "dayGridMonth",

        headerToolbar: {
            left: "prev,next today",
            center: "title",
            right: "dayGridMonth,timeGridWeek,timeGridDay"
        },

        selectable: true,
        editable: true,
        eventResizableFromStart: true,

        slotMinTime: "07:00:00",
        slotMaxTime: "20:00:00",
        slotDuration: "00:15:00",

        height: "auto",

        events: "/appointments/events_json",

        /* =====================================================
           CRÉATION RDV
           - Mois : heures par défaut
           - Semaine / Jour : vraies heures
        ===================================================== */
        select(info) {
            const title = prompt("Titre du rendez-vous");
            if (!title) {
                calendar.unselect();
                return;
            }

            let start = info.start;
            let end = info.end;

            // Cas vue MOIS (pas d'heure)
            if (!info.startStr.includes("T")) {
                start = new Date(info.startStr + "T09:00");
                end = new Date(info.startStr + "T10:00");
            }

            fetch("/appointments/create", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    title: title,
                    date: start.toISOString().slice(0, 10),
                    start_time: start.toTimeString().slice(0, 5),
                    end_time: end.toTimeString().slice(0, 5)
                })
            })
            .then(r => r.json())
            .then(data => {
                if (!data.success) {
                    alert("Erreur création RDV");
                }
                calendar.refetchEvents();
            })
            .catch(() => alert("Erreur réseau"));

            calendar.unselect();
        },

        /* =====================================================
           DRAG & RESIZE
        ===================================================== */
        eventDrop: persistEvent,
        eventResize: persistEvent,

        /* =====================================================
           MODIFICATION AU CLIC
        ===================================================== */
        eventClick(info) {
            const e = info.event;

            const newTitle = prompt("Modifier le titre", e.title);
            if (!newTitle) return;

            const start = e.start;
            const end = e.end;

            fetch("/appointments/update_from_calendar", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    id: e.id,
                    date: start.toISOString().slice(0, 10),
                    start_time: start.toTimeString().slice(0, 5),
                    end_time: end ? end.toTimeString().slice(0, 5) : start.toTimeString().slice(0, 5),
                    title: newTitle
                })
            })
            .then(r => r.json())
            .then(data => {
                if (!data.success) {
                    alert("Erreur modification RDV");
                    calendar.refetchEvents();
                } else {
                    e.setProp("title", newTitle);
                }
            })
            .catch(() => {
                alert("Erreur réseau");
                calendar.refetchEvents();
            });
        },

        /* =====================================================
           INFO BULLE
        ===================================================== */
        eventDidMount(info) {
            const createdBy = info.event.extendedProps.created_by;
            if (createdBy) {
                info.el.title = "Créé par : " + createdBy;
            }
        }
    });

    calendar.render();

    /* =====================================================
       PERSIST DRAG / RESIZE
    ===================================================== */
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
                end_time: end ? end.toTimeString().slice(0, 5) : start.toTimeString().slice(0, 5)
            })
        })
        .then(res => {
            if (!res.ok) {
                alert("Erreur mise à jour RDV");
                info.revert();
            }
        })
        .catch(() => {
            alert("Erreur réseau");
            info.revert();
        });
    }
});
