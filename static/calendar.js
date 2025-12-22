document.addEventListener("DOMContentLoaded", function () {

  const calendarEl = document.getElementById("calendar");
  if (!calendarEl) return;

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

    // =====================
    // CRÉATION RDV
    // =====================
    select(info) {
      const title = prompt("Titre du rendez-vous");
      if (!title) {
        calendar.unselect();
        return;
      }

      // startStr/endStr existent, mais endStr peut être null selon la vue
      const startDate = info.start;
      const endDate = info.end;

      const date = startDate.toISOString().slice(0, 10);
      const time = startDate.toTimeString().slice(0, 5);

      // si pas de end: on met +1h par défaut
      let end_time = null;
      if (endDate) {
        end_time = endDate.toTimeString().slice(0, 5);
      } else {
        end_time = addMinutesHHMM(time, 60);
      }

      fetch("/appointments/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title, date, time, end_time })
      })
        .then(r => r.json())
        .then(data => {
          if (!data.success) {
            alert(data.message || "Erreur création RDV");
            return;
          }
          calendar.refetchEvents();
        })
        .catch(() => alert("Erreur création RDV"));

      calendar.unselect();
    },

    // =====================
    // DRAG & RESIZE
    // =====================
    eventDrop: persistEvent,
    eventResize: persistEvent,

    // =====================
    // CLIC: MODIFIER / SUPPRIMER + HEURES
    // =====================
    eventClick(info) {
      const e = info.event;

      const createdBy = e.extendedProps.created_by ? `\nCréé par: ${e.extendedProps.created_by}` : "";
      const action = prompt(
        `Titre du rendez-vous (ou tape SUPPRIMER pour supprimer)${createdBy}`,
        e.title
      );

      if (!action) return;

      if (action.trim().toLowerCase() === "supprimer") {
        if (!confirm("Confirmer la suppression du rendez-vous ?")) return;

        fetch(`/appointments/${e.id}/delete`, { method: "POST" })
          .then(r => r.json())
          .then(data => {
            if (!data.success) {
              alert(data.message || "Erreur suppression");
              return;
            }
            e.remove();
          })
          .catch(() => alert("Erreur suppression"));
        return;
      }

      // Demande heures
      const start = e.start;
      const end = e.end;

      const newStart = prompt("Heure de début (HH:MM)", start.toTimeString().slice(0, 5));
      if (!newStart) return;

      const newEnd = prompt("Heure de fin (HH:MM)", end ? end.toTimeString().slice(0, 5) : addMinutesHHMM(newStart, 60));
      if (!newEnd) return;

      fetch(`/appointments/${e.id}/update`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: action,
          date: start.toISOString().slice(0, 10),
          time: newStart,
          end_time: newEnd
        })
      })
        .then(r => r.json())
        .then(data => {
          if (!data.success) {
            alert(data.message || "Erreur modification");
            calendar.refetchEvents();
            return;
          }
          calendar.refetchEvents();
        })
        .catch(() => {
          alert("Erreur modification");
          calendar.refetchEvents();
        });
    },

    // =====================
    // INFO BULLE
    // =====================
    eventDidMount(info) {
      const createdBy = info.event.extendedProps.created_by;
      if (createdBy) {
        info.el.title = "Créé par : " + createdBy;
      }
    }
  });

  calendar.render();

  function persistEvent(info) {
    const start = info.event.start;
    const end = info.event.end;

    const date = start.toISOString().slice(0, 10);
    const time = start.toTimeString().slice(0, 5);
    const end_time = end ? end.toTimeString().slice(0, 5) : addMinutesHHMM(time, 60);

    fetch("/appointments/update_from_calendar", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        id: info.event.id,
        date,
        time,
        end_time
      })
    })
      .then(async (res) => {
        if (!res.ok) {
          alert("Erreur mise à jour");
          info.revert();
          return;
        }
        const data = await res.json().catch(() => null);
        if (data && data.success === false) {
          alert(data.message || "Erreur mise à jour");
          info.revert();
        }
      })
      .catch(() => {
        alert("Erreur mise à jour");
        info.revert();
      });
  }

  function addMinutesHHMM(hhmm, minutes) {
    try {
      const [h, m] = hhmm.split(":").map(Number);
      const total = (h * 60 + m + minutes) % (24 * 60);
      const nh = String(Math.floor(total / 60)).padStart(2, "0");
      const nm = String(total % 60).padStart(2, "0");
      return `${nh}:${nm}`;
    } catch {
      return "10:00";
    }
  }
});
