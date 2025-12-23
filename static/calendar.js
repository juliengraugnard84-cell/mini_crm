document.addEventListener("DOMContentLoaded", function () {

    const calendarEl = document.getElementById("calendar");
    if (!calendarEl) return;

    const calendar = new FullCalendar.Calendar(calendarEl, {
        locale: "fr",
        initialView: "timeGridWeek",
        selectable: true,
        editable: true,
        firstDay: 1,
        slotMinTime: "07:00:00",
        slotMaxTime: "20:00:00",

        events: "/appointments/events",

        select(info) {
            const title = prompt("Titre du rendez-vous");
            if (!title) return;

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
            .then(() => calendar.refetchEvents());
        },

        eventDrop: saveEvent,
        eventResize: saveEvent,

        eventClick(info) {
            if (!confirm("Supprimer ce rendez-vous ?")) return;

            fetch("/appointments/delete", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ id: info.event.id })
            })
            .then(() => calendar.refetchEvents());
        }
    });

    calendar.render();

    function saveEvent(info) {
        fetch("/appointments/update", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                id: info.event.id,
                title: info.event.title,
                start: info.event.start.toISOString(),
                end: info.event.end.toISOString()
            })
        })
        .then(res => {
            if (!res.ok) info.revert();
        });
    }
});
