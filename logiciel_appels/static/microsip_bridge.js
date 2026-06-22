const fetchJson = async (url, options = {}) => {
  const response = await fetch(url, options);
  const data = await response
    .json()
    .catch(() => ({ ok: false, error: "Reponse JSON invalide." }));

  if (!response.ok || data.ok === false) {
    throw new Error(data.error || `Erreur ${response.status}`);
  }
  return data;
};

const bootMicrosipBridge = () => {
  const config = window.CALLFLOW_MICROSIP;
  if (!config) {
    return;
  }

  const statusCard = document.getElementById("microsip-status-card");
  const statusTitle = document.getElementById("microsip-status-title");
  const statusCopy = document.getElementById("microsip-status-copy");
  const numberInput = document.getElementById("dialed_number");
  const contactSelect = document.getElementById("dialer-contact");
  const callButton = document.getElementById("microsip-call-button");
  const hangupButton = document.getElementById("microsip-hangup-button");

  const setStatus = (title, copy, tone = "info") => {
    if (statusCard) {
      statusCard.dataset.tone = tone;
    }
    if (statusTitle) {
      statusTitle.textContent = title;
    }
    if (statusCopy) {
      statusCopy.textContent = copy;
    }
  };

  const withBusy = async (button, busyLabel, callback) => {
    if (!button) {
      await callback();
      return;
    }

    const originalLabel = button.textContent;
    button.disabled = true;
    button.textContent = busyLabel;

    try {
      await callback();
    } finally {
      button.disabled = false;
      button.textContent = originalLabel;
    }
  };

  const syncDialedNumberFromContact = () => {
    if (!contactSelect || !numberInput) {
      return;
    }
    const selected = contactSelect.selectedOptions[0];
    if (!selected) {
      return;
    }
    const phone = selected.dataset.phone || "";
    if (phone) {
      numberInput.value = phone;
    }
  };

  const buildPayload = (sourceButton) => {
    const payload = {
      contact_id: sourceButton?.dataset.contactId || contactSelect?.value || "",
      dialed_number: sourceButton?.dataset.number || numberInput?.value || "",
    };
    return payload;
  };

  const dialWithMicrosip = async (sourceButton) => {
    const label =
      sourceButton?.dataset.label ||
      numberInput?.value.trim() ||
      sourceButton?.dataset.number ||
      "le numero demande";
    const payload = buildPayload(sourceButton);

    if (!String(payload.dialed_number || "").trim()) {
      setStatus(
        "Numero manquant",
        "Renseigne un numero, une extension ou selectionne un contact avant d'appeler.",
        "warning",
      );
      return;
    }

    await withBusy(sourceButton || callButton, "Lancement...", async () => {
      const data = await fetchJson(config.dialUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      const dialedNumber = data.dialed_number || payload.dialed_number;
      setStatus(
        "MicroSIP lance",
        `La demande d'appel vers ${label} (${dialedNumber}) a ete envoyee au softphone local.`,
        "success",
      );
    });
  };

  const hangupWithMicrosip = async () => {
    await withBusy(hangupButton, "Raccrochage...", async () => {
      await fetchJson(config.hangupUrl, {
        method: "POST",
      });
      setStatus(
        "Raccrochage demande",
        "MicroSIP a recu l'ordre de terminer les appels en cours sur ce poste.",
        "info",
      );
    });
  };

  if (contactSelect && numberInput) {
    contactSelect.addEventListener("change", syncDialedNumberFromContact);
  }

  document.querySelectorAll("[data-microsip-dial]").forEach((button) => {
    button.addEventListener("click", async () => {
      try {
        await dialWithMicrosip(button);
      } catch (error) {
        setStatus("Echec MicroSIP", error.message, "danger");
      }
    });
  });

  if (callButton) {
    callButton.addEventListener("click", async () => {
      try {
        await dialWithMicrosip();
      } catch (error) {
        setStatus("Echec MicroSIP", error.message, "danger");
      }
    });
  }

  if (hangupButton) {
    hangupButton.addEventListener("click", async () => {
      try {
        await hangupWithMicrosip();
      } catch (error) {
        setStatus("Raccrochage impossible", error.message, "danger");
      }
    });
  }

  if (config.enabled) {
    setStatus(
      "MicroSIP pret",
      `CallFlow utilisera ${config.displayPath || "MicroSIP.exe"} pour lancer les appels sur ce PC.`,
      "success",
    );
  } else {
    setStatus(
      "MicroSIP introuvable",
      "Installe le softphone ou renseigne MICROSIP_EXECUTABLE dans le fichier .env.",
      "warning",
    );
  }
};

bootMicrosipBridge();
