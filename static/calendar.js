document.addEventListener("DOMContentLoaded", function () {
    const calendarEl = document.getElementById("calendar");
    if (!calendarEl) {
        console.error("DIV #calendar introuvable");
        return;
    }

    const calendar = new FullCalendar.Calendar(calendarEl, {
        initialView: "dayGridMonth",
        locale: "fr",
        firstDay: 1,
        selectable: true,
        editable: true,
        height: "auto",

        headerToolbar: {
            left: "prev,next today",
            center: "title",
            right: "dayGridMonth,timeGridWeek,timeGridDay"
        },

        events: "/appointments/events_json",

        select(info) {
            const title = prompt("Titre du rendez-vous");
            if (!title) return;

            fetch("/appointments/create", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    title: title,
                    date: info.startStr.slice(0, 10),
                    start_time: "09:00",
                    end_time: "10:00"
                })
            })
            .then(r => r.json())
            .then(() => calendar.refetchEvents());
        }
    });

    calendar.render();
});
