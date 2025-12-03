// ============================================================
//    FullCalendar — Version simple mais qui MARCHE
// ============================================================

document.addEventListener("DOMContentLoaded", function () {

    console.log("📅 calendar.js chargé");

    const calendarEl = document.getElementById("calendar");
    if (!calendarEl) {
        console.error("❌ Impossible de trouver #calendar");
        return;
    }

    // Initialisation du calendrier
    const calendar = new FullCalendar.Calendar(calendarEl, {
        locale: "fr",
        initialView: "dayGridMonth",
        height: "auto",

        headerToolbar: {
            left: "prev,next today",
            center: "title",
            right: "dayGridMonth,timeGridWeek,timeGridDay"
        },

        // Charge les rendez-vous depuis Flask
        events: "/appointments/events_json",

        // 🟢 CLIC SUR UNE CASE → créer un RDV
        dateClick: function(info) {
            console.log("🟢 Date cliquée :", info.dateStr);
            // On envoie vers le formulaire de création avec la date pré-remplie
            window.location.href = `/appointments/new?date=${info.dateStr}`;
        },

        // 🔵 CLIC SUR UN EVENT → modifier le RDV
        eventClick: function(info) {
            console.log("🔵 RDV cliqué, id =", info.event.id);
            window.location.href = `/appointments/${info.event.id}/edit`;
        }
    });

    calendar.render();
});
