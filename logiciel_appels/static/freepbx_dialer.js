import {
  buildDialDestination,
  describeProfile,
  extractRemoteIdentity,
  findAgentById,
  mergeConfigWithProfile,
  profileComplete,
  readProfile,
} from "./freepbx_shared.js";

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

const bootDialer = () => {
  const form = document.querySelector("[data-freepbx-dialer]");
  const config = window.CALLFLOW_FREEPBX;
  if (!form || !config) {
    return;
  }

  const numberInput = document.getElementById("dialed_number");
  const telLink = document.getElementById("tel-link");
  const contactSelect = document.getElementById("dialer-contact");
  const clearButton = document.getElementById("clear-number");
  const connectButton = document.getElementById("freepbx-connect-button");
  const callButton = document.getElementById("freepbx-call-button");
  const hangupButton = document.getElementById("freepbx-hangup-button");
  const statusCard = document.getElementById("freepbx-status-card");
  const statusTitle = document.getElementById("freepbx-status-title");
  const statusCopy = document.getElementById("freepbx-status-copy");
  const profileSummary = document.getElementById("freepbx-profile-summary");
  const incomingCard = document.getElementById("incoming-call-card");
  const incomingCopy = document.getElementById("incoming-call-copy");
  const answerButton = document.getElementById("answer-call-button");
  const rejectButton = document.getElementById("reject-call-button");
  const remoteAudio = document.getElementById("remote-audio");

  const state = {
    agents: Array.isArray(config.agents) ? config.agents : [],
    serverConfig: null,
    sipModule: null,
    simpleUser: null,
    profileSignature: "",
    isRegistered: false,
    currentCallId: null,
    currentDirection: "outgoing",
    currentLabel: "",
    callStartedAt: 0,
    callAnswered: false,
  };

  const setTone = (tone) => {
    if (statusCard) {
      statusCard.dataset.tone = tone;
    }
  };

  const setStatus = (title, copy, tone = "info") => {
    if (statusTitle) {
      statusTitle.textContent = title;
    }
    if (statusCopy) {
      statusCopy.textContent = copy;
    }
    setTone(tone);
  };

  const setConnectLabel = (label) => {
    if (connectButton) {
      connectButton.textContent = label;
    }
  };

  const updateProfileSummary = (profile) => {
    if (!profileSummary) {
      return;
    }

    const title = profileSummary.querySelector("strong");
    const copy = profileSummary.querySelector("small");
    const currentAgent = findAgentById(state.agents, profile.agentId);
    const agentName = profile.agentName || currentAgent?.name || "";

    if (title) {
      title.textContent = agentName
        ? `${agentName}${profile.extension ? ` - Ext ${profile.extension}` : ""}`
        : profile.extension
          ? `Extension ${profile.extension}`
        : "Profil incomplet";
    }
    if (copy) {
      copy.textContent = describeProfile(profile);
    }
  };

  const syncTelLink = () => {
    const value = numberInput.value.trim();
    telLink.href = value ? `tel:${value}` : "#";
    telLink.textContent = value ? `tel:${value}` : "tel:";
  };

  const syncCall = async (callId, payload) => {
    if (!callId) {
      return;
    }
    try {
      await fetchJson(
        config.callSyncUrl.replace("__CALL_ID__", String(callId)),
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(payload),
        },
      );
    } catch (_error) {
      // Le journal local reste secondaire par rapport a l'appel.
    }
  };

  const resetCallState = () => {
    state.currentCallId = null;
    state.currentDirection = "outgoing";
    state.currentLabel = "";
    state.callStartedAt = 0;
    state.callAnswered = false;
    hangupButton.disabled = true;
    callButton.disabled = !state.isRegistered;
    incomingCard.hidden = true;
    answerButton.disabled = false;
    rejectButton.disabled = false;
  };

  const finalizeCall = async (fallbackStatus, providerStatus, summary = "") => {
    const durationSeconds = state.callStartedAt
      ? Math.max(Math.round((Date.now() - state.callStartedAt) / 1000), 0)
      : 0;
    const status = state.callAnswered
      ? "completed"
      : fallbackStatus;
    const label = state.currentLabel || "le correspondant";

    await syncCall(state.currentCallId, {
      status,
      provider_status: providerStatus,
      summary,
      ended: true,
      duration_seconds: durationSeconds,
    });

    resetCallState();
    if (status === "completed") {
      setStatus(
        "Appel termine",
        `Communication finie avec ${label}. L'extension reste connectee.`,
        "success",
      );
    } else if (status === "missed") {
      setStatus(
        "Appel manque",
        `Aucune communication etablie avec ${label}. L'extension reste connectee.`,
        "warning",
      );
    } else {
      setStatus(
        "Sans reponse",
        `Aucune reponse obtenue pour ${label}. L'extension reste connectee.`,
        "warning",
      );
    }
  };

  const getProfile = () =>
    mergeConfigWithProfile(state.serverConfig || {}, readProfile());

  const requireProfile = () => {
    const profile = getProfile();
    updateProfileSummary(profile);
    if (!profileComplete(profile)) {
      throw new Error(
        "Le profil agent est incomplet. Renseigne l'URL WSS, le domaine SIP, l'extension et le mot de passe.",
      );
    }
    return profile;
  };

  const getSignature = (profile) => JSON.stringify(profile);

  const loadSdk = async () => {
    if (state.sipModule) {
      return state.sipModule;
    }

    const sdkUrl =
      state.serverConfig?.sdk_import_url ||
      "https://cdn.jsdelivr.net/npm/sip.js@0.21.2/+esm";
    state.sipModule = await import(sdkUrl);
    return state.sipModule;
  };

  const teardownUser = async () => {
    if (!state.simpleUser) {
      return;
    }

    try {
      if (typeof state.simpleUser.hangup === "function") {
        await state.simpleUser.hangup();
      }
    } catch (_error) {
      // Rien a faire si aucune session n'est active.
    }

    try {
      if (typeof state.simpleUser.unregister === "function") {
        await state.simpleUser.unregister();
      }
    } catch (_error) {
      // Rien a faire si l'utilisateur n'etait plus enregistre.
    }

    try {
      if (typeof state.simpleUser.disconnect === "function") {
        await state.simpleUser.disconnect();
      }
    } catch (_error) {
      // Rien a faire si la socket etait deja fermee.
    }

    state.simpleUser = null;
    state.isRegistered = false;
    state.profileSignature = "";
    setConnectLabel("Connecter FreePBX");
  };

  const createDelegate = () => ({
    onCallReceived: async () => {
      const remote = extractRemoteIdentity(state.simpleUser);
      const profile = getProfile();
      state.currentDirection = "incoming";
      state.currentLabel = remote.label;
      state.callStartedAt = Date.now();
      state.callAnswered = false;
      incomingCard.hidden = false;
      incomingCopy.textContent = `Appel entrant de ${remote.label}.`;
      hangupButton.disabled = false;
      callButton.disabled = true;
      setStatus("Appel entrant", `Communication entrante de ${remote.label}.`, "warning");

      try {
        const startData = await fetchJson(config.callStartUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            agent_id: profile.agentId || null,
            dialed_number: remote.target,
            direction: "incoming",
            provider: "freepbx",
          }),
        });
        state.currentCallId = startData.call_id;
        await syncCall(startData.call_id, {
          provider_status: "ringing",
        });
      } catch (_error) {
        state.currentCallId = null;
      }
    },
    onCallAnswered: async () => {
      state.callAnswered = true;
      setStatus(
        "En ligne",
        `Conversation active avec ${state.currentLabel || "le correspondant"}.`,
        "success",
      );
      await syncCall(state.currentCallId, {
        status: "in_progress",
        provider_status: "answered",
      });
    },
    onCallHangup: async () => {
      const fallbackStatus =
        state.currentDirection === "incoming" ? "missed" : "no_answer";
      await finalizeCall(fallbackStatus, "hangup");
    },
  });

  const ensureRegistered = async () => {
    state.serverConfig = state.serverConfig || (await fetchJson(config.configUrl));
    const profile = requireProfile();
    const signature = getSignature(profile);

    if (state.simpleUser && state.isRegistered && state.profileSignature === signature) {
      setStatus(
        "Extension deja connectee",
        `FreePBX est deja enregistre pour ${profile.extension}.`,
        "success",
      );
      return profile;
    }

    if (state.simpleUser && state.profileSignature !== signature) {
      await teardownUser();
    }

    if (!state.simpleUser) {
      const sipModule = await loadSdk();
      const SimpleUser =
        sipModule.SimpleUser ||
        sipModule.default?.SimpleUser;

      if (!SimpleUser) {
        throw new Error("Impossible de charger le client SIP.js.");
      }

      state.simpleUser = new SimpleUser(profile.wssUrl, {
        aor: `sip:${profile.extension}@${profile.sipDomain}`,
        delegate: createDelegate(),
        media: {
          remote: {
            audio: remoteAudio,
          },
        },
        userAgentOptions: {
          authorizationUsername: profile.authUser || profile.extension,
          authorizationPassword: profile.password,
          displayName: profile.displayName || profile.extension,
        },
      });
      state.profileSignature = signature;
    }

    setConnectLabel("Connexion...");
    connectButton.disabled = true;
    callButton.disabled = true;

    try {
      await state.simpleUser.connect();
      setStatus(
        "Connexion FreePBX",
        `Enregistrement de l'extension ${profile.extension}...`,
        "info",
      );
      await state.simpleUser.register();
      state.isRegistered = true;
      setConnectLabel("Reconnecter FreePBX");
      callButton.disabled = false;
      setStatus(
        "Extension connectee",
        `Le poste ${profile.extension} est enregistre sur ${profile.sipDomain}.`,
        "success",
      );
      return profile;
    } finally {
      connectButton.disabled = false;
    }
  };

  const handleOutgoingError = async (message) => {
    setStatus("Appel impossible", message, "danger");
    await finalizeCall("no_answer", "client_error", message);
  };

  const connectFreepbx = async () => {
    try {
      await ensureRegistered();
    } catch (error) {
      const message = error?.message || "Connexion FreePBX impossible.";
      setStatus("Connexion impossible", message, "danger");
      callButton.disabled = !profileComplete(getProfile());
    }
  };

  const startCall = async () => {
    try {
      const profile = await ensureRegistered();
      const destination = buildDialDestination(
        numberInput.value,
        profile.outboundPrefix,
      );

      if (!destination) {
        throw new Error("Ajoute une destination valide avant d'appeler.");
      }

      const contactId = contactSelect.value.trim();
      const startData = await fetchJson(config.callStartUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          agent_id: profile.agentId || null,
          contact_id: contactId || null,
          dialed_number: destination,
          direction: "outgoing",
          provider: "freepbx",
        }),
      });

      state.currentCallId = startData.call_id;
      state.currentDirection = "outgoing";
      state.currentLabel = destination;
      state.callStartedAt = Date.now();
      state.callAnswered = false;
      callButton.disabled = true;
      hangupButton.disabled = false;

      setStatus("Composition", `Appel en cours vers ${destination}...`, "info");
      await syncCall(startData.call_id, {
        provider_status: "dialing",
      });

      const result = state.simpleUser.call(destination);
      if (result && typeof result.catch === "function") {
        result.catch(async (error) => {
          await handleOutgoingError(error?.message || "Echec de l'appel sortant.");
        });
      }
    } catch (error) {
      const message = error?.message || "Impossible de demarrer l'appel.";
      setStatus("FreePBX indisponible", message, "danger");
      if (state.currentCallId) {
        await syncCall(state.currentCallId, {
          status: "no_answer",
          provider_status: "client_error",
          summary: message,
          ended: true,
        });
      }
      resetCallState();
    }
  };

  const answerIncoming = async () => {
    if (!state.simpleUser) {
      return;
    }
    try {
      setStatus("Connexion", "Prise de l'appel entrant...", "info");
      await state.simpleUser.answer();
    } catch (error) {
      const message = error?.message || "Impossible de repondre a l'appel.";
      setStatus("Reponse impossible", message, "danger");
      await finalizeCall("missed", "answer_error", message);
    }
  };

  const hangupCall = async () => {
    if (!state.simpleUser) {
      return;
    }
    try {
      setStatus("Raccrochage", "Fin de la communication...", "info");
      await state.simpleUser.hangup();
    } catch (error) {
      const message = error?.message || "Impossible de raccrocher proprement.";
      setStatus("Raccrochage partiel", message, "warning");
      const fallbackStatus =
        state.currentDirection === "incoming" ? "missed" : "no_answer";
      await finalizeCall(fallbackStatus, "local_hangup_error", message);
    }
  };

  const loadConfigStatus = async () => {
    try {
      state.serverConfig = await fetchJson(config.configUrl);
      const profile = getProfile();
      updateProfileSummary(profile);

      if (profileComplete(profile)) {
        if (state.agents.length && !profile.agentId) {
          setStatus(
            "Profil telephonie pret",
            "Selectionne aussi un agent dans l'onglet FreePBX pour remonter les stats equipe.",
            "warning",
          );
        } else {
          setStatus(
            "Profil agent pret",
            "Clique sur Connecter FreePBX pour enregistrer l'extension de ce navigateur.",
            "info",
          );
        }
        callButton.disabled = false;
        return;
      }

      if (state.serverConfig.enabled) {
        setStatus(
          "Profil a completer",
          "Les valeurs serveur sont chargees. Il manque encore le profil agent local.",
          "warning",
        );
      } else {
        setStatus(
          "FreePBX a preparer",
          `Variables serveur manquantes : ${state.serverConfig.missing.join(", ") || "aucune"}.`,
          "warning",
        );
      }
    } catch (error) {
      const profile = getProfile();
      updateProfileSummary(profile);
      setStatus("Configuration FreePBX", error.message, "danger");
    }
  };

  document.querySelectorAll("[data-key]").forEach((button) => {
    button.addEventListener("click", () => {
      numberInput.value += button.dataset.key;
      syncTelLink();
    });
  });

  contactSelect.addEventListener("change", () => {
    const option = contactSelect.options[contactSelect.selectedIndex];
    numberInput.value = option?.dataset.phone || "";
    syncTelLink();
  });

  clearButton.addEventListener("click", () => {
    numberInput.value = "";
    syncTelLink();
  });

  window.addEventListener("storage", (event) => {
    if (event.key === "callflowFreepbxProfile") {
      const profile = getProfile();
      updateProfileSummary(profile);
      callButton.disabled = !state.isRegistered && !profileComplete(profile);
    }
  });

  numberInput.addEventListener("input", syncTelLink);
  connectButton.addEventListener("click", connectFreepbx);
  callButton.addEventListener("click", startCall);
  hangupButton.addEventListener("click", hangupCall);
  answerButton.addEventListener("click", answerIncoming);
  rejectButton.addEventListener("click", hangupCall);

  syncTelLink();
  callButton.disabled = true;
  loadConfigStatus();
};

document.addEventListener("DOMContentLoaded", bootDialer);
