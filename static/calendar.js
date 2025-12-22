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

            const startTime = prompt(
                "Heure de début (HH:MM)",
                info.startStr.slice(11, 16)
            );
            if (!startTime) {
                calendar.unselect();
                return;
            }

            const endTime = prompt(
                "Heure de fin (HH:MM)",
                info.endStr
                    ? info.endStr.slice(11, 16)
                    : startTime
            );
            if (!endTime) {
                calendar.unselect();
                return;
            }

            fetch("/appointments/create", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    title: title,
                    date: info.startStr.slice(0, 10),
                    start_time: startTime,
                    end_time: endTime,
                    client_id: null
                })
            })
            .then(r => r.json())
            .then(data => {
                if (!data.success) {
                    alert(data.message || "Erreur création RDV");
                    return;
                }
                calendar.refetchEvents();
            })
            .catch(() => alert("Erreur réseau création RDV"));

            calendar.unselect();
        },

        /* =====================
           DRAG & RESIZE
        ===================== */
        eventDrop: persistEvent,
        eventResize: persistEvent,

        /* =====================
           ÉDITION AU CLIC
        ===================== */
        eventClick(info) {
            const e = info.event;

            const title = prompt("Titre du rendez-vous", e.title);
            if (!title) return;

            const startTime = prompt(
                "Heure de début (HH:MM)",
                e.start.toTimeString().slice(0, 5)
            );
            if (!startTime) return;

            const endTime = prompt(
                "Heure de fin (HH:MM)",
                e.end
                    ? e.end.toTimeString().slice(0, 5)
                    : startTime
            );
            if (!endTime) return;

            fetch("/appointments/update_from_calendar", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    id: e.id,
                    date: e.start.toISOString().slice(0, 10),
                    start_time: startTime,
                    end_time: endTime
                })
            })
            .then(r => r.json())
            .then(data => {
                if (!data.success) {
                    alert(data.message || "Erreur modification");
                    calendar.refetchEvents();
                } else {
                    calendar.refetchEvents();
                }
            })
            .catch(() => {
                alert("Erreur réseau modification");
                calendar.refetchEvents();
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
                end_time: end
                    ? end.toTimeString().slice(0, 5)
                    : start.toTimeString().slice(0, 5)
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
