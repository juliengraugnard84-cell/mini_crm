const STORAGE_KEY = "callflowFreepbxProfile";

const trimValue = (value) => (value == null ? "" : String(value).trim());

export const sanitizeProfile = (raw = {}) => ({
  agentId: trimValue(raw.agentId),
  agentName: trimValue(raw.agentName),
  wssUrl: trimValue(raw.wssUrl),
  sipDomain: trimValue(raw.sipDomain),
  extension: trimValue(raw.extension),
  authUser: trimValue(raw.authUser),
  password: trimValue(raw.password),
  displayName: trimValue(raw.displayName),
  outboundPrefix: trimValue(raw.outboundPrefix),
});

export const readProfile = () => {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return sanitizeProfile();
    }
    return sanitizeProfile(JSON.parse(raw));
  } catch (_error) {
    return sanitizeProfile();
  }
};

export const writeProfile = (profile) => {
  const clean = sanitizeProfile(profile);
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(clean));
  } catch (_error) {
    // Le navigateur peut bloquer le stockage local selon sa politique.
  }
  return clean;
};

export const clearProfile = () => {
  try {
    window.localStorage.removeItem(STORAGE_KEY);
  } catch (_error) {
    // Rien a faire si le stockage local n'est pas accessible.
  }
};

export const mergeConfigWithProfile = (config = {}, savedProfile = {}) => {
  const defaults = sanitizeProfile({
    agentId: "",
    agentName: "",
    wssUrl: config.wss_url,
    sipDomain: config.sip_domain,
    extension: config.default_extension,
    authUser: config.default_auth_user,
    password: "",
    displayName: config.display_name,
    outboundPrefix: config.outbound_prefix,
  });
  const saved = sanitizeProfile(savedProfile);

  return sanitizeProfile({
    agentId: saved.agentId,
    agentName: saved.agentName,
    wssUrl: saved.wssUrl || defaults.wssUrl,
    sipDomain: saved.sipDomain || defaults.sipDomain,
    extension: saved.extension || defaults.extension,
    authUser: saved.authUser || defaults.authUser,
    password: saved.password,
    displayName: saved.displayName || defaults.displayName,
    outboundPrefix: saved.outboundPrefix || defaults.outboundPrefix,
  });
};

export const buildAor = (profile) => {
  const clean = sanitizeProfile(profile);
  if (!clean.extension || !clean.sipDomain) {
    return "";
  }
  return `sip:${clean.extension}@${clean.sipDomain}`;
};

export const profileComplete = (profile) => {
  const clean = sanitizeProfile(profile);
  return Boolean(
    clean.wssUrl &&
      clean.sipDomain &&
      clean.extension &&
      clean.password,
  );
};

export const buildDialDestination = (value, outboundPrefix = "") => {
  const raw = trimValue(value);
  if (!raw) {
    return "";
  }

  if (/^sip:/i.test(raw)) {
    return raw.replace(/\s+/g, "");
  }

  const compact = raw.replace(/\s+/g, "");
  const cleaned = compact.replace(/[^A-Za-z0-9@+*#_.:-]/g, "");
  if (!cleaned) {
    return "";
  }

  if (cleaned.includes("@")) {
    return cleaned.startsWith("sip:") ? cleaned : `sip:${cleaned}`;
  }

  if (/^[0-9+*#]+$/.test(cleaned)) {
    const prefix = trimValue(outboundPrefix);
    if (
      prefix &&
      cleaned.length >= 6 &&
      !cleaned.startsWith(prefix) &&
      !cleaned.startsWith("+")
    ) {
      return `${prefix}${cleaned}`;
    }
  }

  return cleaned;
};

export const findAgentById = (agents = [], agentId = "") => {
  const lookup = trimValue(agentId);
  if (!lookup) {
    return null;
  }
  return agents.find((agent) => trimValue(agent?.id) === lookup) || null;
};

export const applyAgentTemplate = (profile = {}, agent = null) => {
  const clean = sanitizeProfile(profile);
  if (!agent) {
    return clean;
  }

  return sanitizeProfile({
    ...clean,
    agentId: agent.id,
    agentName: agent.name,
    extension: agent.extension || clean.extension,
    authUser: agent.auth_user || clean.authUser,
    displayName: agent.display_name || agent.name || clean.displayName,
    outboundPrefix: agent.outbound_prefix || clean.outboundPrefix,
  });
};

export const describeProfile = (profile) => {
  const clean = sanitizeProfile(profile);
  const aor = buildAor(clean);
  if (!aor && !clean.agentName) {
    return "AOR a definir";
  }

  const details = [];
  if (clean.agentName) {
    details.push(`agent ${clean.agentName}`);
  }
  if (aor) {
    details.push(aor);
  }
  if (clean.authUser && clean.authUser !== clean.extension) {
    details.push(`auth ${clean.authUser}`);
  }
  if (clean.wssUrl) {
    details.push(clean.wssUrl);
  }
  return details.join(" | ");
};

export const extractRemoteIdentity = (simpleUser) => {
  const identity = simpleUser?.session?.remoteIdentity;
  const displayName = trimValue(identity?.displayName);
  const user = trimValue(identity?.uri?.user);
  const host = trimValue(identity?.uri?.host);
  const target = user && host ? `${user}@${host}` : user || host || "";

  return {
    label: displayName || target || "correspondant inconnu",
    target: target || displayName || "inconnu",
  };
};
