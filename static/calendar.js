console.log("calendar.js chargé !");

document.addEventListener("DOMContentLoaded", function () {
  const calendarEl = document.getElementById("calendar");

  if (!calendarEl) {
    console.error("Erreur : élément #calendar introuvable dans calendar.html");
    return;
  }

  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content") || "";

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

    events: "/appointments/events_json",

    dateClick(info) {
      console.log("Date cliquée :", info.dateStr);
      alert("Clique sur la date : " + info.dateStr);
    },

    eventDrop(info) {
      const start = info.event.startStr;

      const payload = {
        id: info.event.id,
        date: start.split("T")[0],
        time: start.split("T")[1]?.substring(0, 5) || null
      };

      fetch("/appointments/update_from_calendar", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken
        },
        body: JSON.stringify(payload)
      })
        .then(res => {
          if (!res.ok) {
            alert("Erreur lors de la mise à jour de l'événement.");
          }
        })
        .catch(err => console.error("Erreur fetch update :", err));
    }
  });

  calendar.render();
});
