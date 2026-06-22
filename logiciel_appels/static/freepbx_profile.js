import {
  applyAgentTemplate,
  buildAor,
  clearProfile,
  describeProfile,
  findAgentById,
  mergeConfigWithProfile,
  profileComplete,
  readProfile,
  writeProfile,
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

const bootProfileSetup = () => {
  const form = document.querySelector("[data-freepbx-profile]");
  const config = window.CALLFLOW_FREEPBX_PROFILE;
  if (!form || !config) {
    return;
  }

  const fields = {
    agentTemplateId: document.getElementById("agent_template_id"),
    wssUrl: document.getElementById("wss_url"),
    sipDomain: document.getElementById("sip_domain"),
    extension: document.getElementById("extension"),
    authUser: document.getElementById("auth_user"),
    password: document.getElementById("password"),
    displayName: document.getElementById("display_name"),
    outboundPrefix: document.getElementById("outbound_prefix"),
  };

  const summaryCard = document.getElementById("profile-summary-card");
  const statusCard = document.getElementById("profile-status-card");
  const statusTitle = document.getElementById("profile-status-title");
  const statusCopy = document.getElementById("profile-status-copy");
  const saveButton = document.getElementById("save-profile-button");
  const clearButton = document.getElementById("clear-profile-button");

  const state = {
    agents: Array.isArray(config.agents) ? config.agents : [],
    serverConfig: null,
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

  const applyProfile = (profile) => {
    fields.agentTemplateId.value = profile.agentId || "";
    fields.wssUrl.value = profile.wssUrl;
    fields.sipDomain.value = profile.sipDomain;
    fields.extension.value = profile.extension;
    fields.authUser.value = profile.authUser;
    fields.password.value = profile.password;
    fields.displayName.value = profile.displayName;
    fields.outboundPrefix.value = profile.outboundPrefix;
  };

  const getSelectedAgent = () =>
    findAgentById(state.agents, fields.agentTemplateId.value);

  const readFormProfile = () => ({
    agentId: fields.agentTemplateId.value,
    agentName: getSelectedAgent()?.name || "",
    wssUrl: fields.wssUrl.value,
    sipDomain: fields.sipDomain.value,
    extension: fields.extension.value,
    authUser: fields.authUser.value,
    password: fields.password.value,
    displayName: fields.displayName.value,
    outboundPrefix: fields.outboundPrefix.value,
  });

  const renderSummary = (profile) => {
    if (!summaryCard) {
      return;
    }

    const title = summaryCard.querySelector("strong");
    const copy = summaryCard.querySelector("small");
    const aor = buildAor(profile);

    if (title) {
      title.textContent = profile.agentName
        ? `${profile.agentName}${aor ? ` - ${aor}` : ""}`
        : aor || "Profil incomplet";
    }
    if (copy) {
      copy.textContent = describeProfile(profile);
    }
  };

  const refreshStatusFromProfile = (profile) => {
    if (profileComplete(profile)) {
      setStatus(
        "Profil agent pret",
        "Le composeur peut maintenant se connecter a FreePBX depuis ce navigateur.",
        "success",
      );
      return;
    }

    if (state.agents.length && !profile.agentId) {
      setStatus(
        "Agent a choisir",
        "Selectionne un agent de l'equipe ou remplis le profil a la main pour ce navigateur.",
        "warning",
      );
      return;
    }

    if (state.serverConfig?.enabled) {
      setStatus(
        "Extension a completer",
        "Ajoute au minimum le mot de passe SIP ou ajuste l'extension pour finaliser ce poste.",
        "warning",
      );
      return;
    }

    setStatus(
      "Configuration manquante",
      "Renseigne l'URL WSS, le domaine SIP, l'extension et le mot de passe agent.",
      "warning",
    );
  };

  const syncUi = (profile) => {
    renderSummary(profile);
    refreshStatusFromProfile(profile);
  };

  const loadDefaults = async () => {
    try {
      state.serverConfig = await fetchJson(config.configUrl);
      let merged = mergeConfigWithProfile(state.serverConfig, readProfile());
      const selectedAgent = findAgentById(state.agents, merged.agentId);
      if (selectedAgent) {
        merged = applyAgentTemplate(merged, selectedAgent);
      }
      applyProfile(merged);
      syncUi(merged);
    } catch (error) {
      const localOnly = readProfile();
      applyProfile(localOnly);
      renderSummary(localOnly);
      setStatus("Lecture impossible", error.message, "danger");
    }
  };

  saveButton.addEventListener("click", () => {
    const saved = writeProfile(readFormProfile());
    syncUi(saved);
  });

  clearButton.addEventListener("click", () => {
    clearProfile();
    const reset = mergeConfigWithProfile(state.serverConfig || {}, {});
    applyProfile(reset);
    syncUi(reset);
  });

  form.addEventListener("input", () => {
    renderSummary(readFormProfile());
  });

  fields.agentTemplateId.addEventListener("change", () => {
    const selectedAgent = getSelectedAgent();
    const updated = selectedAgent
      ? applyAgentTemplate(readFormProfile(), selectedAgent)
      : readFormProfile();
    applyProfile(updated);
    syncUi(updated);
  });

  loadDefaults();
};

document.addEventListener("DOMContentLoaded", bootProfileSetup);
