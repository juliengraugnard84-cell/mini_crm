document.addEventListener("DOMContentLoaded", function () {

    const calendarEl = document.getElementById("calendar");
    if (!calendarEl) return;

    const modalEl = document.getElementById("eventModal");
    const modal = new bootstrap.Modal(modalEl);

    const calendar = new FullCalendar.Calendar(calendarEl, {
        initialView: "dayGridMonth",
        locale: "fr",
        firstDay: 1,

        selectable: true,
        editable: true,

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
            if (!title) return calendar.unselect();

            const start = info.start;
            const end = info.end || new Date(start.getTime() + 30 * 60000);

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
           MODALE ÉDITION
        ===================== */
        eventClick(info) {
            const e = info.event;

            document.getElementById("eventId").value = e.id;
            document.getElementById("eventTitle").value = e.title;
            document.getElementById("eventStart").value = e.start.toTimeString().slice(0,5);
            document.getElementById("eventEnd").value = e.end.toTimeString().slice(0,5);
            document.getElementById("eventDescription").value =
                e.extendedProps.description || "";

            modal.show();
        }
    });

    calendar.render();

    /* =====================
       SAUVEGARDE ÉDITION
    ===================== */
    document.getElementById("eventForm").addEventListener("submit", function (e) {
        e.preventDefault();

        const id = document.getElementById("eventId").value;

        fetch("/appointments/update_from_calendar", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                id: id,
                date: calendar.getEventById(id).start.toISOString().slice(0,10),
                start_time: document.getElementById("eventStart").value,
                end_time: document.getElementById("eventEnd").value
            })
        })
        .then(r => r.json())
        .then(() => {
            modal.hide();
            calendar.refetchEvents();
        });
    });

    /* =====================
       SUPPRESSION RDV
    ===================== */
    document.getElementById("deleteEventBtn").addEventListener("click", function () {
        if (!confirm("Supprimer ce rendez-vous ?")) return;

        const id = document.getElementById("eventId").value;

        fetch(`/appointments/delete/${id}`, { method: "POST" })
            .then(() => {
                modal.hide();
                calendar.refetchEvents();
            });
    });

    function persistEvent(info) {
        const start = info.event.start;
        const end = info.event.end;

        fetch("/appointments/update_from_calendar", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                id: info.event.id,
                date: start.toISOString().slice(0,10),
                start_time: start.toTimeString().slice(0,5),
                end_time: end.toTimeString().slice(0,5)
            })
        }).catch(() => info.revert());
    }
});
