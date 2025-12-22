document.addEventListener("DOMContentLoaded", function () {

    const calendarEl = document.getElementById("calendar");
    if (!calendarEl) return;

    const calendar = new FullCalendar.Calendar(calendarEl, {
        initialView: "dayGridMonth",
        locale: "fr",
        selectable: true,
        editable: true,
        height: "auto",

        headerToolbar: {
            left: "prev,next today",
            center: "title",
            right: "dayGridMonth,timeGridWeek,timeGridDay"
        },

        // Chargement des événements
        events: "/appointments/events_json",

        // ✅ CRÉATION D'UN RDV
        dateClick(info) {
            const title = prompt("Titre du rendez-vous :");
            if (!title) return;

            fetch("/appointments/create", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    title: title,
                    date: info.dateStr
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
                    title: title,
                    start: info.dateStr,
                    backgroundColor: "#2563eb",
                    borderColor: "#2563eb"
                });
            })
            .catch(err => {
                console.error(err);
                alert("Erreur réseau");
            });
        },

        // ✅ DRAG & DROP
        eventDrop(info) {
            const start = info.event.startStr;

            fetch("/appointments/update_from_calendar", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    id: info.event.id,
                    date: start.split("T")[0],
                    time: start.split("T")[1]?.substring(0, 5) || null
                })
            }).then(res => {
                if (!res.ok) {
                    alert("Erreur mise à jour");
                    info.revert();
                }
            });
        }
    });

    calendar.render();
});
