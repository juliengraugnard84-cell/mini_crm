document.addEventListener("DOMContentLoaded", function () {

    const calendarEl = document.getElementById("calendar");
    if (!calendarEl) return;

    const calendar = new FullCalendar.Calendar(calendarEl, {
        locale: "fr",

        /* ===== VUES ===== */
        initialView: "dayGridMonth",
        firstDay: 1,

        headerToolbar: {
            left: "prev,next today",
            center: "title",
            right: "dayGridMonth,timeGridWeek,timeGridDay"
        },

        /* ===== INTERACTIONS ===== */
        selectable: true,
        editable: true,
        eventResizableFromStart: true,

        /* ===== HEURES ===== */
        slotMinTime: "07:00:00",
        slotMaxTime: "20:00:00",
        slotDuration: "00:15:00",

        /* ===== DATA ===== */
        events: "/appointments/events",

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
                    start_time: info.startStr.slice(11, 16) || "09:00",
                    end_time: info.endStr.slice(11, 16) || "10:00"
                })
            })
            .then(res => {
                if (!res.ok) throw new Error();
                calendar.refetchEvents();
            })
            .catch(() => alert("Erreur création RDV"));

            calendar.unselect();
        },

        /* =====================
           DRAG & RESIZE
        ===================== */
        eventDrop: saveEvent,
        eventResize: saveEvent,

        /* =====================
           SUPPRESSION AU CLIC
        ===================== */
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
            if (!res.ok) {
                alert("Erreur mise à jour");
                info.revert();
            }
        })
        .catch(() => info.revert());
    }
});
