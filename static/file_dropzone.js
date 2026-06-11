document.addEventListener("DOMContentLoaded", () => {
    const zones = document.querySelectorAll("[data-file-dropzone]");

    if (!zones.length) {
        return;
    }

    const formatBytes = (bytes) => {
        if (!Number.isFinite(bytes) || bytes <= 0) {
            return "0 o";
        }

        const units = ["o", "Ko", "Mo", "Go"];
        let value = bytes;
        let unitIndex = 0;

        while (value >= 1024 && unitIndex < units.length - 1) {
            value /= 1024;
            unitIndex += 1;
        }

        const rounded = unitIndex === 0 ? Math.round(value) : value.toFixed(value >= 10 ? 0 : 1);
        return `${rounded} ${units[unitIndex]}`;
    };

    const assignFiles = (input, files) => {
        if (!window.DataTransfer) {
            return false;
        }

        const transfer = new DataTransfer();
        files.forEach((file) => transfer.items.add(file));
        input.files = transfer.files;
        input.dispatchEvent(new Event("change", { bubbles: true }));
        return true;
    };

    zones.forEach((zone) => {
        const input = zone.querySelector("[data-file-input]");
        const surface = zone.querySelector("[data-file-surface]") || zone;
        const summary = zone.querySelector("[data-file-summary]");
        const list = zone.querySelector("[data-file-list]");

        if (!input || !surface || !summary || !list) {
            return;
        }

        let dragDepth = 0;

        const render = () => {
            const files = Array.from(input.files || []);
            zone.classList.toggle("is-filled", files.length > 0);
            list.innerHTML = "";

            if (!files.length) {
                summary.textContent = "Aucun fichier selectionne";
                list.hidden = true;
                return;
            }

            const totalSize = files.reduce((sum, file) => sum + (file.size || 0), 0);
            summary.textContent = `${files.length} fichier${files.length > 1 ? "s" : ""} selectionne${files.length > 1 ? "s" : ""} • ${formatBytes(totalSize)}`;

            files.forEach((file) => {
                const chip = document.createElement("div");
                chip.className = "crm-file-drop-chip";
                const name = document.createElement("span");
                name.textContent = file.name;

                const size = document.createElement("small");
                size.textContent = formatBytes(file.size || 0);

                chip.appendChild(name);
                chip.appendChild(size);
                list.appendChild(chip);
            });

            list.hidden = false;
        };

        ["dragenter", "dragover"].forEach((eventName) => {
            surface.addEventListener(eventName, (event) => {
                event.preventDefault();
                dragDepth += 1;
                zone.classList.add("is-dragover");
            });
        });

        ["dragleave", "dragend"].forEach((eventName) => {
            surface.addEventListener(eventName, (event) => {
                event.preventDefault();
                dragDepth = Math.max(0, dragDepth - 1);
                if (dragDepth === 0) {
                    zone.classList.remove("is-dragover");
                }
            });
        });

        surface.addEventListener("drop", (event) => {
            event.preventDefault();
            dragDepth = 0;
            zone.classList.remove("is-dragover");

            const droppedFiles = Array.from(event.dataTransfer?.files || []);
            if (!droppedFiles.length) {
                return;
            }

            const nextFiles = input.multiple ? droppedFiles : droppedFiles.slice(0, 1);

            if (!assignFiles(input, nextFiles)) {
                summary.textContent = `${nextFiles.length} fichier${nextFiles.length > 1 ? "s" : ""} pret${nextFiles.length > 1 ? "s" : ""} a etre ajoute${nextFiles.length > 1 ? "s" : ""}. Cliquez pour confirmer la selection.`;
            }
        });

        surface.addEventListener("keydown", (event) => {
            if (event.key !== "Enter" && event.key !== " ") {
                return;
            }

            event.preventDefault();
            input.click();
        });

        input.addEventListener("change", render);
        render();
    });

    const docKindLabels = {
        factures: "factures",
        mandats: "mandats",
        contrats: "contrats",
        summary: "summary",
        autres: "autres",
    };

    const docUploadForms = document.querySelectorAll("[data-doc-upload-form]");

    docUploadForms.forEach((form) => {
        const autoToggle = form.querySelector("[data-doc-auto-toggle]");
        const manualInput = form.querySelector("[data-doc-name-input]");
        const manualField = form.querySelector("[data-doc-manual-field]");
        const note = form.querySelector("[data-doc-name-note]");
        const kindInputs = Array.from(form.querySelectorAll("[data-doc-kind-input]"));
        const extraCodeInput = form.querySelector("[data-doc-extra-code-input]");
        const contextName = (form.dataset.docContextName || "dossier").trim();

        if (!autoToggle || !manualInput || !note || !kindInputs.length) {
            return;
        }

        const renderNamingState = () => {
            const selectedKind = kindInputs.find((input) => input.checked)?.value || "autres";
            const kindLabel = docKindLabels[selectedKind] || docKindLabels.autres;
            const autoEnabled = autoToggle.checked;
            const extraCode = (extraCodeInput?.value || "").trim();

            manualInput.disabled = autoEnabled;
            manualInput.setAttribute("aria-disabled", autoEnabled ? "true" : "false");

            if (manualField) {
                manualField.classList.toggle("is-disabled", autoEnabled);
            }

            if (autoEnabled) {
                note.textContent = `Nom auto : ${contextName} + ${kindLabel}${extraCode ? ` + ${extraCode}` : ""}`;
            } else {
                note.textContent = "Nom personnalise actif. Le champ ci-dessous sera utilise pour nommer le document.";
            }
        };

        autoToggle.addEventListener("change", renderNamingState);
        kindInputs.forEach((input) => input.addEventListener("change", renderNamingState));

        if (extraCodeInput) {
            extraCodeInput.addEventListener("input", renderNamingState);
        }

        renderNamingState();
    });
});
