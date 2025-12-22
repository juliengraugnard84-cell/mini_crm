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
        nowIndicator: true,

        slotMinTime: "07:00:00",
        slotMaxTime: "20:00:00",
        slotDuration: "00:15:00",

        headerToolbar: {
            left: "prev,next today",
            center: "title",
            right: "dayGridMonth,timeGridWeek,timeGridDay"
        },

        /* =====================
           CHARGEMENT DES RDV
        ===================== */
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

            fetch("/appointments/create", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    title: title,
                    date: info.startStr.slice(0, 10),
                    time: info.startStr.slice(11, 16)
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
                console.error("❌ Erreur création RDV", err);
                alert("Erreur serveur");
            });

            calendar.unselect();
        },

        /* =====================
           DÉPLACEMENT RDV
        ===================== */
        eventDrop(info) {
            persistEvent(info);
        },

        /* =====================
           REDIMENSIONNEMENT RDV
        ===================== */
        eventResize(info) {
            persistEvent(info);
        }

    });

    calendar.render();

    /* =====================
       SAUVEGARDE BACKEND
    ===================== */
    function persistEvent(info) {

        const start = info.event.start;
        if (!start) {
            info.revert();
            return;
        }

        fetch("/appointments/update_from_calendar", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                id: info.event.id,
                date: start.toISOString().slice(0, 10),
                time: start.toTimeString().slice(0, 5)
            })
        })
        .then(res => {
            if (!res.ok) {
                alert("Erreur mise à jour RDV");
                info.revert();
            }
        })
        .catch(err => {
            console.error("❌ Erreur update RDV", err);
            info.revert();
        });
    }

});
