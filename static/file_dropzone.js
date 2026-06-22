document.addEventListener("DOMContentLoaded", () => {
    const zones = document.querySelectorAll("[data-file-dropzone]");

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

    const buildFileKey = (file) => [
        file.name || "",
        file.size || 0,
        file.lastModified || 0,
        file.type || "",
    ].join("::");

    const syncInputFiles = (input, files) => {
        if (!window.DataTransfer) {
            return false;
        }

        const transfer = new DataTransfer();
        files.forEach((file) => transfer.items.add(file));
        input.files = transfer.files;
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
        let selectedFiles = Array.from(input.files || []);

        const render = () => {
            zone.classList.toggle("is-filled", selectedFiles.length > 0);
            list.innerHTML = "";

            if (!selectedFiles.length) {
                summary.textContent = "Aucun fichier selectionne";
                list.hidden = true;
                return;
            }

            const totalSize = selectedFiles.reduce((sum, file) => sum + (file.size || 0), 0);
            summary.textContent = `${selectedFiles.length} fichier${selectedFiles.length > 1 ? "s" : ""} selectionne${selectedFiles.length > 1 ? "s" : ""} - ${formatBytes(totalSize)}`;

            selectedFiles.forEach((file, index) => {
                const chip = document.createElement("div");
                chip.className = "crm-file-drop-chip";

                const label = document.createElement("span");
                label.textContent = file.name;
                label.title = file.name;

                const size = document.createElement("small");
                size.textContent = formatBytes(file.size || 0);

                chip.appendChild(label);
                chip.appendChild(size);

                if (input.multiple) {
                    const removeBtn = document.createElement("button");
                    removeBtn.type = "button";
                    removeBtn.className = "crm-file-drop-remove";
                    removeBtn.dataset.fileRemoveIndex = String(index);
                    removeBtn.setAttribute("aria-label", `Retirer ${file.name}`);
                    removeBtn.textContent = "x";
                    chip.appendChild(removeBtn);
                }

                list.appendChild(chip);
            });

            list.hidden = false;
        };

        const applyFiles = (incomingFiles, append = true) => {
            const files = Array.from(incomingFiles || []).filter(Boolean);

            if (!files.length) {
                render();
                return;
            }

            if (!input.multiple) {
                selectedFiles = files.slice(0, 1);
            } else if (append) {
                const merged = new Map();
                selectedFiles.forEach((file) => merged.set(buildFileKey(file), file));
                files.forEach((file) => merged.set(buildFileKey(file), file));
                selectedFiles = Array.from(merged.values());
            } else {
                selectedFiles = files;
            }

            syncInputFiles(input, selectedFiles);
            render();
        };

        const removeAt = (index) => {
            if (!Number.isInteger(index) || index < 0 || index >= selectedFiles.length) {
                return;
            }

            selectedFiles.splice(index, 1);
            syncInputFiles(input, selectedFiles);
            render();
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

            applyFiles(droppedFiles, Boolean(input.multiple));
        });

        surface.addEventListener("keydown", (event) => {
            if (event.key !== "Enter" && event.key !== " ") {
                return;
            }

            event.preventDefault();
            input.click();
        });

        input.addEventListener("change", () => {
            const pickedFiles = Array.from(input.files || []);
            if (!pickedFiles.length) {
                render();
                return;
            }

            applyFiles(pickedFiles, Boolean(input.multiple));

            if (window.DataTransfer) {
                input.value = "";
                syncInputFiles(input, selectedFiles);
            }
        });

        list.addEventListener("click", (event) => {
            const button = event.target.closest("[data-file-remove-index]");
            if (!button) {
                return;
            }

            removeAt(Number(button.dataset.fileRemoveIndex));
        });

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
        kindInputs.forEach((item) => item.addEventListener("change", renderNamingState));

        if (extraCodeInput) {
            extraCodeInput.addEventListener("input", renderNamingState);
        }

        renderNamingState();
    });

    const previewModal = document.getElementById("crmDocumentPreviewModal");
    const previewFrame = document.getElementById("crmDocumentPreviewFrame");
    const previewTitle = document.getElementById("crmDocumentPreviewTitle");
    const previewOpen = document.getElementById("crmDocumentPreviewOpen");

    if (previewModal && previewFrame && window.bootstrap?.Modal) {
        const modal = window.bootstrap.Modal.getOrCreateInstance(previewModal);

        document.addEventListener("click", (event) => {
            const link = event.target.closest("[data-doc-preview-link]");
            if (!link) {
                return;
            }

            event.preventDefault();

            const href = link.getAttribute("href");
            if (!href) {
                return;
            }

            if (previewTitle) {
                previewTitle.textContent = link.dataset.docPreviewTitle || "Previsualisation du document";
            }

            if (previewOpen) {
                previewOpen.href = href;
            }

            previewFrame.src = href;
            modal.show();
        });

        previewModal.addEventListener("hidden.bs.modal", () => {
            previewFrame.src = "about:blank";
            if (previewOpen) {
                previewOpen.removeAttribute("href");
            }
        });
    }
});
