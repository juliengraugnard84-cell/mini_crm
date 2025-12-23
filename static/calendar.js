document.addEventListener("DOMContentLoaded", function () {

    const calendarEl = document.getElementById("calendar");
    if (!calendarEl) return;

    const calendar = new FullCalendar.Calendar(calendarEl, {
        locale: "fr",
        firstDay: 1,
        selectable: true,
        editable: true,
        initialView: "dayGridMonth",

        headerToolbar: {
            left: "prev,next today",
            center: "title",
            right: "dayGridMonth,timeGridWeek,timeGridDay"
        },

        events: "/appointments/events_json",

        select(info) {
            let startTime = "09:00";
            let endTime = "10:00";

            if (calendar.view.type !== "dayGridMonth") {
                startTime = info.startStr.slice(11, 16);
                endTime = info.endStr.slice(11, 16);
            } else {
                startTime = prompt("Heure de début (HH:MM)", "09:00");
                endTime = prompt("Heure de fin (HH:MM)", "10:00");
                if (!startTime || !endTime) return;
            }

            const title = prompt("Titre du rendez-vous");
            if (!title) return;

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
            .then(() => calendar.refetchEvents());
        },

        eventClick(info) {
            const e = info.event;
            const title = prompt("Modifier le titre", e.title);
            if (!title) return;

            if (!confirm("Supprimer ce rendez-vous ?\nAnnuler = Modifier")) {
                fetch("/appointments/update", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        id: e.id,
                        title: title,
                        date: e.start.toISOString().slice(0, 10),
                        start_time: e.start.toTimeString().slice(0, 5),
                        end_time: e.end.toTimeString().slice(0, 5)
                    })
                }).then(() => calendar.refetchEvents());
            } else {
                fetch("/appointments/delete", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ id: e.id })
                }).then(() => calendar.refetchEvents());
            }
        },

        eventDrop: persistMove,
        eventResize: persistMove,

        eventDidMount(info) {
            const createdBy = info.event.extendedProps.created_by;
            if (createdBy) {
                info.el.title = "Créé par : " + createdBy;
            }
        }
    });

    calendar.render();

    function persistMove(info) {
        fetch("/appointments/update_from_calendar", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                id: info.event.id,
                date: info.event.start.toISOString().slice(0, 10),
                start_time: info.event.start.toTimeString().slice(0, 5),
                end_time: info.event.end.toTimeString().slice(0, 5)
            })
        }).catch(() => info.revert());
    }
});
