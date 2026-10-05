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


def name_words(value):
    value = unicodedata.normalize('NFKD', value or '').casefold()
    value = ''.join(c for c in value if not unicodedata.combining(c))
    return re.findall(r'[^\W_]+', value)


def extended_name_matches(left, right):
    left, right = name_words(left), name_words(right)
    if not left or not right or left == right:
        return False
    shorter, longer = (left, right) if len(left) < len(right) else (right, left)
    return len(shorter) < len(longer) and any(
        longer[i:i + len(shorter)] == shorter for i in range(len(longer) - len(shorter) + 1)
    )


def match_reasons(candidate, existing):
    """Return matching nonempty criteria; partial matches warn, full matches block."""
    names = {normalize_name(n) for n in candidate.get("names", [])} - {""}
    sirets = {normalize_reference(s) for s in candidate.get("sirets", [])} - {""}
    references = {normalize_reference(r) for r in candidate.get("references", [])} - {""}
    matching_names = names & ({normalize_name(n) for n in existing.get("names", [])} - {""})
    extended_name = not matching_names and any(
        extended_name_matches(left, right)
        for left in candidate.get('names', []) for right in existing.get('names', [])
    )
    matching_sirets = sirets & ({normalize_reference(s) for s in existing.get("sirets", [])} - {""})
    matching_references = references & {
        normalize_reference(r) for r in existing.get("references", [])
    }
    return (["Raison sociale"] if matching_names else
            ["Nom du dossier complété"] if extended_name else []) + (["SIRET"] if matching_sirets else []) + [
        "PDL/PCE : " + reference for reference in sorted(matching_references)
    ]


def is_blocking_match(reasons):
    return ("Raison sociale" in reasons and "SIRET" in reasons
            and any(reason.startswith("PDL/PCE : ") for reason in reasons))
