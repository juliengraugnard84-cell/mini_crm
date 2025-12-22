console.log("calendar.js chargé");

document.addEventListener("DOMContentLoaded", function () {

    const calendarEl = document.getElementById("calendar");
    const currentUser = window.CURRENT_USERNAME || "inconnu";

    if (!calendarEl) {
        console.error("❌ #calendar introuvable");
        return;
    }

    const calendar = new FullCalendar.Calendar(calendarEl, {
        initialView: "dayGridMonth",
        locale: "fr",

        selectable: true,
        editable: true,
        eventResizableFromStart: true,
        height: "auto",

        headerToolbar: {
            left: "prev,next today",
            center: "title",
            right: "dayGridMonth,timeGridWeek,timeGridDay"
        },

        // 🔄 Events depuis Flask
        events: "/appointments/events_json",

        // =====================================================
        // 📅 CRÉATION RDV
        // =====================================================
        dateClick(info) {
            const title = prompt("Titre du rendez-vous :");
            if (!title) return;

            const startTime = prompt("Heure de début (HH:MM)", "09:00");
            if (!startTime) return;

            const endTime = prompt("Heure de fin (HH:MM)", "10:00");
            if (!endTime) return;

            const fullTitle = `${title} — ${currentUser}`;

            fetch("/appointments/create", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    title: fullTitle,
                    date: info.dateStr,
                    time: startTime,
                    end_time: endTime
                })
            })
            .then(res => res.json())
            .then(data => {
                if (!data.success) {
                    alert(data.message || "Erreur création RDV");
                    return;
                }

                calendar.addEvent({
                    id: data.id,
                    title: fullTitle,
                    start: `${info.dateStr}T${startTime}:00`,
                    end: `${info.dateStr}T${endTime}:00`,
                    backgroundColor: "#2563eb",
                    borderColor: "#2563eb"
                });
            })
            .catch(err => {
                console.error("Erreur création RDV:", err);
                alert("Erreur serveur");
            });
        },

        // =====================================================
        // 🔀 DÉPLACEMENT RDV
        // =====================================================
        eventDrop(info) {
            const start = info.event.start;
            const end = info.event.end;

            fetch("/appointments/update_from_calendar", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    id: info.event.id,
                    date: start.toISOString().slice(0, 10),
                    time: start.toTimeString().slice(0, 5),
                    end_time: end ? end.toTimeString().slice(0, 5) : null
                })
            })
            .then(res => {
                if (!res.ok) {
                    alert("Erreur déplacement RDV");
                    info.revert();
                }
            })
            .catch(() => {
                alert("Erreur serveur");
                info.revert();
            });
        },

        // =====================================================
        // ⏱️ MODIFICATION HEURE (resize)
        // =====================================================
        eventResize(info) {
            const start = info.event.start;
            const end = info.event.end;

            fetch("/appointments/update_from_calendar", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    id: info.event.id,
                    date: start.toISOString().slice(0, 10),
                    time: start.toTimeString().slice(0, 5),
                    end_time: end.toTimeString().slice(0, 5)
                })
            })
            .then(res => {
                if (!res.ok) {
                    alert("Erreur modification heure");
                    info.revert();
                }
            })
            .catch(() => {
                alert("Erreur serveur");
                info.revert();
            });
        }
    });

    calendar.render();
});
