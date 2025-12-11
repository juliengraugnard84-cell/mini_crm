console.log("calendar.js chargé !");

document.addEventListener("DOMContentLoaded", function () {

    const calendarEl = document.getElementById("calendar");

    if (!calendarEl) {
        console.error("Erreur : élément #calendar introuvable dans agenda.html");
        return;
    }

    // -----------------------------------------
    //  CONFIG FULLCALENDAR
    // -----------------------------------------
    const calendar = new FullCalendar.Calendar(calendarEl, {

        initialView: "dayGridMonth",
        locale: "fr",
        selectable: true,
        editable: true,     // drag & drop activé
        height: "auto",

        headerToolbar: {
            left: "prev,next today",
            center: "title",
            right: "dayGridMonth,timeGridWeek,timeGridDay"
        },

        // Récupération des événements du backend Flask
        events: "/appointments/events_json",

        // -----------------------------------------
        // CLIC SUR UNE DATE
        // -----------------------------------------
        dateClick(info) {
            console.log("Date cliquée :", info.dateStr);

            // Tu pourras remplacer par l'ouverture de ton modal
            alert("Clique sur la date : " + info.dateStr);
        },

        // -----------------------------------------
        // DRAG & DROP — Mise à jour du backend
        // -----------------------------------------
        eventDrop(info) {

            const start = info.event.startStr;

            const payload = {
                id: info.event.id,
                date: start.split("T")[0],
                time: start.split("T")[1]?.substring(0, 5) || null
            };

            console.log("Mise à jour d’un événement :", payload);

            fetch("/appointments/update_from_calendar", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            }).then(res => {
                if (!res.ok) {
                    alert("Erreur lors de la mise à jour de l'événement.");
                }
            }).catch(err => {
                console.error("Erreur fetch update :", err);
            });
        }
    });

    // Lancer le calendrier
    calendar.render();
});
