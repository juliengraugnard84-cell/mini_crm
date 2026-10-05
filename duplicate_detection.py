"""Matching rules shared by CRM dossier and quotation entry."""
import re
import unicodedata


ACTIVE_STATUSES = {"", "nouveau", "en_cours", "en_attente", "gagne"}


def normalize_name(value):
    value = unicodedata.normalize("NFKD", value or "").casefold()
    return "".join(c for c in value if c.isalnum() and not unicodedata.combining(c))


def normalize_reference(value):
    # Ignore formatting, preserve leading zeros; never match empty values.
    return re.sub(r"[\s.\-/]", "", value or "").upper()


def match_reasons(candidate, existing):
    reasons = []
    names = {normalize_name(n) for n in candidate.get("names", [])} - {""}
    sirets = {normalize_reference(s) for s in candidate.get("sirets", [])} - {""}
    references = {normalize_reference(r) for r in candidate.get("references", [])} - {""}
    if names & ({normalize_name(n) for n in existing.get("names", [])} - {""}):
        reasons.append("Raison sociale")
    if sirets & ({normalize_reference(s) for s in existing.get("sirets", [])} - {""}):
        reasons.append("SIRET")
    for reference in sorted(references & {
        normalize_reference(r) for r in existing.get("references", [])
    }):
        reasons.append("PDL/PCE : " + reference)
    return reasons
