console.log("calendar.js chargé !");

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
           CRÉATION RDV (sélection plage)
        =============================== */
        select(info) {
            const title = prompt("Titre du rendez-vous :");
            if (!title) {
                calendar.unselect();
                return;
            }

            const start = info.start;
            const end = info.end;

            const payload = {
                title: title,
                date: start.toISOString().slice(0, 10),
                time: start.toTimeString().slice(0, 5),
                end_time: end.toTimeString().slice(0, 5)
            };

            fetch("/appointments/create", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(payload)
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
                console.error("❌ create error", err);
            });

            calendar.unselect();
        },

        /* ===============================
           DÉPLACEMENT RDV
        =============================== */
        eventDrop(info) {
            updateEvent(info);
        },

        /* ===============================
           REDIMENSIONNEMENT RDV
        =============================== */
        eventResize(info) {
            updateEvent(info);
        },

        /* ===============================
           TOOLTIP (créateur)
        =============================== */
        eventDidMount(info) {
            if (info.event.extendedProps.created_by) {
                info.el.title =
                    "Créé par : " + info.event.extendedProps.created_by;
            }
        }
    });

    calendar.render();

    /* ===============================
       UPDATE BACKEND
    =============================== */
    function updateEvent(info) {
        const start = info.event.start;
        const end = info.event.end;

        const payload = {
            id: info.event.id,
            date: start.toISOString().slice(0, 10),
            time: start.toTimeString().slice(0, 5),
            end_time: end ? end.toTimeString().slice(0, 5) : null
        };

        fetch("/appointments/update_from_calendar", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        })
        .then(res => {
            if (!res.ok) {
                alert("Erreur lors de la mise à jour du RDV");
                info.revert();
            }
        })
        .catch(err => {
            console.error("❌ update error", err);
            info.revert();
        });
    }
});
