import {
  describeProfile,
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

const bootReadiness = () => {
  const config = window.CALLFLOW_READINESS;
  if (!config) {
    return;
  }

  const browserSupportStatus = document.getElementById("browser-support-status");
  const profileReadinessStatus = document.getElementById("profile-readiness-status");
  const microphoneStatus = document.getElementById("microphone-status");
  const speakerStatus = document.getElementById("speaker-status");
  const wssStatus = document.getElementById("wss-status");
  const testMicrophoneButton = document.getElementById("test-microphone-button");
  const testSpeakerButton = document.getElementById("test-speaker-button");
  const testWssButton = document.getElementById("test-wss-button");
  const meterLabel = document.getElementById("meter-label");
  const meterBar = document.getElementById("microphone-meter-bar");
  const deviceList = document.getElementById("device-list");
  const profileCard = document.getElementById("readiness-profile-card");

  const state = {
    analyser: null,
    audioContext: null,
    microphoneStream: null,
    meterFrame: 0,
    profile: mergeConfigWithProfile({}, readProfile()),
    serverConfig: null,
  };

  const setItem = (element, title, copy, tone = "info") => {
    if (!element) {
      return;
    }
    const strong = element.querySelector("strong");
    const paragraph = element.querySelector("p");
    element.dataset.tone = tone;
    if (strong) {
      strong.textContent = title;
    }
    if (paragraph) {
      paragraph.textContent = copy;
    }
  };

  const setMeter = (level) => {
    if (!meterBar) {
      return;
    }
    const percentage = Math.max(4, Math.min(100, Math.round(level * 100)));
    meterBar.style.width = `${percentage}%`;
  };

  const stopMeterLoop = () => {
    if (state.meterFrame) {
      cancelAnimationFrame(state.meterFrame);
      state.meterFrame = 0;
    }
  };

  const startMeterLoop = () => {
    stopMeterLoop();
    if (!state.analyser) {
      return;
    }

    const buffer = new Uint8Array(state.analyser.fftSize);
    const tick = () => {
      if (!state.analyser) {
        return;
      }
      state.analyser.getByteTimeDomainData(buffer);
      let peak = 0;
      for (const value of buffer) {
        peak = Math.max(peak, Math.abs(value - 128) / 128);
      }
      setMeter(peak);
      if (meterLabel) {
        meterLabel.textContent = peak > 0.08
          ? "Signal micro detecte."
          : "Parle dans le micro pour verifier le niveau.";
      }
      state.meterFrame = requestAnimationFrame(tick);
    };

    tick();
  };

  const renderProfileCard = () => {
    if (!profileCard) {
      return;
    }

    const title = profileCard.querySelector("strong");
    const copy = profileCard.querySelector("small");
    const label = state.profile.agentName
      ? `${state.profile.agentName}${state.profile.extension ? ` - Ext ${state.profile.extension}` : ""}`
      : state.profile.extension
        ? `Extension ${state.profile.extension}`
        : "Aucun profil local";

    if (title) {
      title.textContent = label;
    }
    if (copy) {
      copy.textContent = describeProfile(state.profile);
    }
  };

  const renderDevices = async () => {
    if (!navigator.mediaDevices?.enumerateDevices) {
      if (deviceList) {
        deviceList.innerHTML = '<p class="empty">Ce navigateur ne propose pas la liste detaillee des peripheriques.</p>';
      }
      return;
    }

    try {
      const devices = await navigator.mediaDevices.enumerateDevices();
      const relevant = devices.filter(
        (device) => device.kind === "audioinput" || device.kind === "audiooutput",
      );

      if (!relevant.length) {
        deviceList.innerHTML = '<p class="empty">Aucun micro ou peripherique audio visible.</p>';
        return;
      }

      const items = relevant
        .map((device) => {
          const kind = device.kind === "audioinput" ? "Micro" : "Sortie";
          const label = device.label || `${kind} navigateur non nomme`;
          return `<div class="device-item"><strong>${kind}</strong><span>${label}</span></div>`;
        })
        .join("");

      deviceList.innerHTML = items;
    } catch (_error) {
      deviceList.innerHTML = '<p class="empty">Impossible de lire les peripheriques audio du navigateur.</p>';
    }
  };

  const updateBrowserSupport = () => {
    const hasMedia = Boolean(navigator.mediaDevices?.getUserMedia);
    const hasAudioContext = Boolean(window.AudioContext || window.webkitAudioContext);
    const secure = Boolean(window.isSecureContext);

    if (hasMedia && hasAudioContext && secure) {
      setItem(
        browserSupportStatus,
        "Navigateur WebRTC compatible",
        "Le navigateur supporte le micro, l'audio Web et le contexte securise.",
        "success",
      );
      return;
    }

    const issues = [];
    if (!secure) {
      issues.push("page non securisee");
    }
    if (!hasMedia) {
      issues.push("micro non supporte");
    }
    if (!hasAudioContext) {
      issues.push("audio Web indisponible");
    }
    setItem(
      browserSupportStatus,
      "Navigateur a verifier",
      `Blocages detectes : ${issues.join(", ")}.`,
      "warning",
    );
  };

  const updateProfileReadiness = () => {
    renderProfileCard();
    if (profileComplete(state.profile)) {
      setItem(
        profileReadinessStatus,
        "Profil agent pret",
        "Le poste contient assez d'informations pour s'enregistrer sur FreePBX.",
        "success",
      );
      return;
    }

    setItem(
      profileReadinessStatus,
      "Profil agent incomplet",
      "Complete l'URL WSS, le domaine SIP, l'extension et le mot de passe dans l'onglet FreePBX.",
      "warning",
    );
  };

  const requestMicrophone = async () => {
    if (!navigator.mediaDevices?.getUserMedia) {
      setItem(
        microphoneStatus,
        "Micro indisponible",
        "Le navigateur ne permet pas l'acces au microphone.",
        "danger",
      );
      return;
    }

    testMicrophoneButton.disabled = true;
    try {
      if (state.microphoneStream) {
        state.microphoneStream.getTracks().forEach((track) => track.stop());
      }

      state.microphoneStream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const AudioContextCtor = window.AudioContext || window.webkitAudioContext;
      state.audioContext = state.audioContext || new AudioContextCtor();
      if (state.audioContext.state === "suspended") {
        await state.audioContext.resume();
      }

      const source = state.audioContext.createMediaStreamSource(state.microphoneStream);
      state.analyser = state.audioContext.createAnalyser();
      state.analyser.fftSize = 1024;
      source.connect(state.analyser);
      startMeterLoop();
      await renderDevices();

      setItem(
        microphoneStatus,
        "Micro operationnel",
        "Autorisation obtenue. Parle dans le casque pour verifier le niveau.",
        "success",
      );
    } catch (error) {
      setItem(
        microphoneStatus,
        "Micro refuse",
        error?.message || "Le navigateur a bloque l'acces au microphone.",
        "danger",
      );
    } finally {
      testMicrophoneButton.disabled = false;
    }
  };

  const playSpeakerTest = async () => {
    const AudioContextCtor = window.AudioContext || window.webkitAudioContext;
    if (!AudioContextCtor) {
      setItem(
        speakerStatus,
        "Sortie audio indisponible",
        "Ce navigateur ne permet pas le test casque.",
        "danger",
      );
      return;
    }

    testSpeakerButton.disabled = true;
    try {
      state.audioContext = state.audioContext || new AudioContextCtor();
      if (state.audioContext.state === "suspended") {
        await state.audioContext.resume();
      }

      const oscillator = state.audioContext.createOscillator();
      const gain = state.audioContext.createGain();
      oscillator.type = "sine";
      oscillator.frequency.value = 660;
      gain.gain.value = 0.03;
      oscillator.connect(gain);
      gain.connect(state.audioContext.destination);
      oscillator.start();
      oscillator.stop(state.audioContext.currentTime + 0.5);

      setItem(
        speakerStatus,
        "Son de test envoye",
        "Tu devrais entendre un bip court dans le casque ou les haut-parleurs.",
        "success",
      );
      await renderDevices();
    } catch (error) {
      setItem(
        speakerStatus,
        "Test casque impossible",
        error?.message || "Le navigateur n'a pas pu jouer le son de test.",
        "danger",
      );
    } finally {
      testSpeakerButton.disabled = false;
    }
  };

  const testWss = async () => {
    const url = state.profile.wssUrl || state.serverConfig?.wss_url || "";
    if (!url) {
      setItem(
        wssStatus,
        "URL WSS manquante",
        "Ajoute l'adresse FreePBX en wss://.../ws avant de tester le transport.",
        "warning",
      );
      return;
    }

    testWssButton.disabled = true;
    setItem(
      wssStatus,
      "Test WSS en cours",
      `Connexion transport vers ${url}...`,
      "info",
    );

    await new Promise((resolve) => {
      let completed = false;
      const socket = new WebSocket(url, "sip");
      const timeout = window.setTimeout(() => {
        if (completed) {
          return;
        }
        completed = true;
        try {
          socket.close();
        } catch (_error) {
          // Rien a faire.
        }
        setItem(
          wssStatus,
          "WSS non joignable",
          "Aucune ouverture de socket en moins de 5 secondes.",
          "danger",
        );
        resolve();
      }, 5000);

      socket.onopen = () => {
        if (completed) {
          return;
        }
        completed = true;
        window.clearTimeout(timeout);
        setItem(
          wssStatus,
          "Transport WSS joignable",
          "Le navigateur a bien ouvert la socket SIP. Le transport de base repond.",
          "success",
        );
        socket.close();
        resolve();
      };

      socket.onerror = () => {
        if (completed) {
          return;
        }
        completed = true;
        window.clearTimeout(timeout);
        setItem(
          wssStatus,
          "Erreur WSS",
          "Le navigateur n'a pas pu joindre le PBX. Verifie DNS, certificat, port 8089 et URI /ws.",
          "danger",
        );
        resolve();
      };

      socket.onclose = () => {
        if (completed) {
          return;
        }
        completed = true;
        window.clearTimeout(timeout);
        setItem(
          wssStatus,
          "Socket fermee trop tot",
          "Le PBX a ferme la connexion avant ouverture usable. Verifie la configuration WebSocket SIP.",
          "warning",
        );
        resolve();
      };
    });

    testWssButton.disabled = false;
  };

  const load = async () => {
    updateBrowserSupport();
    await renderDevices();

    try {
      state.serverConfig = await fetchJson(config.configUrl);
      state.profile = mergeConfigWithProfile(state.serverConfig, readProfile());
    } catch (_error) {
      state.profile = mergeConfigWithProfile({}, readProfile());
    }

    updateProfileReadiness();
  };

  testMicrophoneButton?.addEventListener("click", requestMicrophone);
  testSpeakerButton?.addEventListener("click", playSpeakerTest);
  testWssButton?.addEventListener("click", testWss);

  window.addEventListener("storage", (event) => {
    if (event.key === "callflowFreepbxProfile") {
      state.profile = mergeConfigWithProfile(state.serverConfig || {}, readProfile());
      updateProfileReadiness();
    }
  });

  window.addEventListener("beforeunload", () => {
    stopMeterLoop();
    if (state.microphoneStream) {
      state.microphoneStream.getTracks().forEach((track) => track.stop());
    }
  });

  load();
};

document.addEventListener("DOMContentLoaded", bootReadiness);
