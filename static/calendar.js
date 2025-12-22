document.addEventListener("DOMContentLoaded", () => {

  const calendar = new FullCalendar.Calendar(
    document.getElementById("calendar"), {

    initialView: "timeGridWeek",
    locale: "fr",
    selectable: true,
    editable: true,
    events: "/appointments/events_json",

    select(info) {
      const title = prompt("Titre du rendez-vous");
      if (!title) return;

      fetch("/appointments/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title,
          date: info.startStr.slice(0,10),
          time: info.startStr.slice(11,16),
          end_time: info.endStr ? info.endStr.slice(11,16) : "10:00"
        })
      })
      .then(() => calendar.refetchEvents());
    },

    eventDrop: update,
    eventResize: update,

    eventClick(info) {
      if (!confirm("Supprimer ce rendez-vous ?")) return;

      fetch(`/appointments/${info.event.id}/delete`, { method: "POST" })
        .then(() => info.event.remove());
    }
  });

  calendar.render();

  function update(info) {
    fetch("/appointments/update_from_calendar", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        id: info.event.id,
        date: info.event.start.toISOString().slice(0,10),
        time: info.event.start.toTimeString().slice(0,5),
        end_time: info.event.end
          ? info.event.end.toTimeString().slice(0,5)
          : "10:00"
      })
    });
  }
});
