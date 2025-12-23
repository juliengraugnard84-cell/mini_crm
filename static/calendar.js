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
        slotDuration: "00:30:00",

        events: "/appointments/events_json",

        /* ===============================
           CRÉATION RDV
        =============================== */
        select(info) {
            const title = prompt("Titre du rendez-vous");
            if (!title) return calendar.unselect();

            let start = info.start;
            let end = info.end;

            // Vue MOIS → heures par défaut
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
                    alert(data.message || "Erreur création RDV");
                }
                calendar.refetchEvents();
            });

            calendar.unselect();
        },

        /* ===============================
           DRAG / RESIZE
        =============================== */
        eventDrop: updateEvent,
        eventResize: updateEvent,

        /* ===============================
           MODIFICATION AU CLIC
        =============================== */
        eventClick(info) {
            const e = info.event;

            const title = prompt("Modifier le titre", e.title);
            if (!title) return;

            fetch("/appointments/update_from_calendar", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    id: e.id,
                    date: e.start.toISOString().slice(0, 10),
                    start_time: e.start.toTimeString().slice(0, 5),
                    end_time: e.end.toTimeString().slice(0, 5),
                    title: title
                })
            })
            .then(r => r.json())
            .then(data => {
                if (!data.success) {
                    alert("Erreur modification");
                    calendar.refetchEvents();
                } else {
                    e.setProp("title", title);
                }
            });
        }
    });

    calendar.render();

    function updateEvent(info) {
        fetch("/appointments/update_from_calendar", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                id: info.event.id,
                date: info.event.start.toISOString().slice(0, 10),
                start_time: info.event.start.toTimeString().slice(0, 5),
                end_time: info.event.end.toTimeString().slice(0, 5)
            })
        })
        .then(r => {
            if (!r.ok) {
                alert("Erreur déplacement RDV");
                info.revert();
            }
        });
    }
});
