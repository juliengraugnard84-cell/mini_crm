console.log("calendar.js chargé !");

document.addEventListener("DOMContentLoaded", function () {

    const calendarEl = document.getElementById("calendar");
    if (!calendarEl) {
        console.error("❌ Élément #calendar introuvable");
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

        /* ===============================
           CHARGEMENT DES RDV
        =============================== */
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
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    title: title,
                    date: start.toISOString().slice(0, 10),
                    time: start.toTimeString().slice(0, 5),
                    end_time: end ? end.toTimeString().slice(0, 5) : null
                })
            })
            .then(res => res.json())
            .then(data => {
                if (!data.success) {
                    alert(data.message || "Erreur création RDV");
                    return;
                }
                calendar.refetchEvents();
            })
            .catch(err => {
                console.error("❌ Erreur création", err);
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
           INFO BULLE
        =============================== */
        eventDidMount(info) {
            const createdBy = info.event.extendedProps.created_by;
            if (createdBy) {
                info.el.title = "Créé par : " + createdBy;
            }
        }
    });

    calendar.render();

    /* ===============================
       SAUVEGARDE BACKEND
    =============================== */
    function persistEvent(info) {
        const start = info.event.start;
        const end = info.event.end;

        fetch("/appointments/update_from_calendar", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                id: info.event.id,
                date: start.toISOString().slice(0, 10),
                time: start.toTimeString().slice(0, 5),
                end_time: end ? end.toTimeString().slice(0, 5) : null
            })
        })
        .then(res => {
            if (!res.ok) {
                alert("Erreur mise à jour RDV");
                info.revert();
            }
        })
        .catch(err => {
            console.error("❌ Erreur update", err);
            info.revert();
        });
    }
});
