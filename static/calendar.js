console.log("calendar.js chargé");

document.addEventListener("DOMContentLoaded", function () {

    const calendarEl = document.getElementById("calendar");
    if (!calendarEl) {
        console.error("❌ #calendar introuvable");
        return;
    }

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

        /* ===============================
           CRÉATION RDV
        =============================== */
        select(info) {

            const title = prompt("Titre du rendez-vous");
            if (!title) {
                calendar.unselect();
                return;
            }

            const start = info.start;
            const end = info.end;

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
                    return;
                }
                calendar.refetchEvents();
            })
            .catch(err => {
                console.error("❌ Création RDV", err);
            });

            calendar.unselect();
        },

        /* ===============================
           DÉPLACEMENT RDV
        =============================== */
        eventDrop(info) {
            persistEvent(info);
        },

        /* ===============================
           REDIMENSIONNEMENT RDV
        =============================== */
        eventResize(info) {
            persistEvent(info);
        },

        /* ===============================
           TOOLTIP
        =============================== */
        eventDidMount(info) {
            info.el.title = info.event.title;
        }
    });

    calendar.render();

    /* ===============================
       SAUVEGARDE BACKEND
    =============================== */
    function persistEvent(info) {

        const start = info.event.start;
        const end = info.event.end;

        if (!start || !end) {
            console.error("❌ start/end manquants");
            info.revert();
            return;
        }

        fetch("/appointments/update_from_calendar", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                id: info.event.id,
                start: start.toISOString(),
                end: end.toISOString()
            })
        })
        .then(res => {
            if (!res.ok) {
                alert("Erreur mise à jour RDV");
                info.revert();
            }
        })
        .catch(err => {
            console.error("❌ Update RDV", err);
            info.revert();
        });
    }
});
