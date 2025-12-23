document.addEventListener("DOMContentLoaded", function () {

    const calendarEl = document.getElementById("calendar");
    if (!calendarEl) return;

    const calendar = new FullCalendar.Calendar(calendarEl, {
        initialView: "dayGridMonth",
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
           CLIC SUR UN JOUR (VUE MOIS)
           → BASCULE EN VUE JOUR
        ===================== */
        dateClick(info) {
            if (calendar.view.type === "dayGridMonth") {
                calendar.changeView("timeGridDay", info.dateStr);
            }
        },

        /* =====================
           CRÉATION RDV (VUES HEURES)
        ===================== */
        select(info) {
            if (!info.start || !info.end) return;

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
            .then(data => {
                if (!data.success) {
                    alert("Erreur création RDV");
                }
                calendar.refetchEvents();
            })
            .catch(() => alert("Erreur création RDV"));

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

            fetch("/appointments/update_from_calendar", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    id: e.id,
                    date: e.start.toISOString().slice(0, 10),
                    start_time: e.start.toTimeString().slice(0, 5),
                    end_time: e.end ? e.end.toTimeString().slice(0, 5) : null
                })
            })
            .then(r => r.json())
            .then(data => {
                if (!data.success) {
                    alert("Erreur modification");
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
                info.el.title = "RDV : " + createdBy;
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
