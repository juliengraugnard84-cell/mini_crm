document.addEventListener("DOMContentLoaded", function () {
    const calendarEl = document.getElementById("calendar");
    if (!calendarEl) return;

    const calendar = new FullCalendar.Calendar(calendarEl, {
        locale: "fr",
        firstDay: 1,
        initialView: "dayGridMonth",

        selectable: true,
        editable: true,

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

            let startTime = "09:00";
            let endTime = "10:00";

            // 👉 SI on est en vue MOIS, on demande les heures
            if (calendar.view.type === "dayGridMonth") {
                startTime = prompt("Heure de début (HH:MM)", "09:00");
                if (!startTime) return;

                endTime = prompt("Heure de fin (HH:MM)", "10:00");
                if (!endTime) return;
            } else {
                startTime = info.startStr.slice(11, 16);
                endTime = info.endStr.slice(11, 16);
            }

            fetch("/appointments/create", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    title: title,
                    date: info.startStr.slice(0, 10),
                    start_time: startTime,
                    end_time: endTime
                })
            })
            .then(res => res.json())
            .then(data => {
                if (!data.success) {
                    alert("Erreur création RDV");
                } else {
                    calendar.refetchEvents();
                }
            });

            calendar.unselect();
        },

        /* =====================
           DRAG & RESIZE
        ===================== */
        eventDrop: persistEvent,
        eventResize: persistEvent,

        eventDidMount(info) {
            if (info.event.extendedProps.created_by) {
                info.el.title =
                    info.event.title +
                    "\nCréé par : " +
                    info.event.extendedProps.created_by;
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
        });
    }
});
