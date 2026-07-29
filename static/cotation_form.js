document.addEventListener("DOMContentLoaded", () => {
    const forms = document.querySelectorAll("[data-cotation-form]");
    forms.forEach((form) => initCotationForm(form));
});

function initCotationForm(form) {
    const energySelect = form.querySelector("[data-energy-select]");
    const energySections = Array.from(form.querySelectorAll("[data-energy-section]"));
    const emptyState = form.querySelector("[data-energy-empty]");
    const status = form.querySelector("[data-energy-status]");
    const deliveryRoot = form.querySelector("[data-delivery-points-root]");

    const energyLabels = {
        electricite: "Electricite",
        gaz: "Gaz",
        elec_gaz: "Electricite & gaz",
    };

    const activeGroups = (value) => {
        if (value === "electricite") {
            return ["electricite"];
        }
        if (value === "gaz") {
            return ["gaz"];
        }
        if (value === "elec_gaz") {
            return ["electricite", "gaz"];
        }
        return [];
    };

    const syncEnergySections = () => {
        if (!energySelect || !energySections.length) {
            return;
        }

        const value = energySelect.value;
        const groups = activeGroups(value);

        energySections.forEach((section) => {
            const shouldShow = groups.includes(section.dataset.energySection);
            section.hidden = !shouldShow;
            section.classList.toggle("is-hidden", !shouldShow);

            section.querySelectorAll("input, select, textarea").forEach((field) => {
                field.disabled = !shouldShow;
            });
        });

        if (emptyState) {
            emptyState.hidden = groups.length > 0;
        }

        if (status) {
            status.textContent = value
                ? `Bloc actif : ${energyLabels[value] || "Demande"}`
                : "Selectionnez une energie pour filtrer automatiquement les blocs de consommation.";
        }

        syncDeliveryPointEnergy();
    };

    let getSiteMode = () => "mono";

    let syncDeliveryPointEnergy = () => {};

    if (deliveryRoot) {
        const modeInputs = Array.from(deliveryRoot.querySelectorAll("[data-site-mode-toggle]"));
        const modeCopy = deliveryRoot.querySelector("[data-site-mode-copy]");
        const list = deliveryRoot.querySelector("[data-delivery-points-list]");
        const addButton = deliveryRoot.querySelector("[data-add-delivery-point]");
        const template = deliveryRoot.querySelector("[data-delivery-point-template]");

        const ensureAtLeastOneCard = () => {
            if (!list || list.querySelector("[data-delivery-point-item]")) {
                return;
            }

            if (!template || !template.content.firstElementChild) {
                return;
            }

            list.appendChild(template.content.firstElementChild.cloneNode(true));
        };

        const getCards = () => Array.from(list.querySelectorAll("[data-delivery-point-item]"));

        getSiteMode = () => {
            const checked = modeInputs.find((input) => input.checked);
            return checked ? checked.value : "mono";
        };

        const setCardFieldsDisabled = (card, disabled) => {
            card.querySelectorAll("input, select, textarea").forEach((field) => {
                field.disabled = disabled;
            });
        };

        const syncPointReferenceLabel = (card) => {
            const energyField = card.querySelector("[data-point-energy]");
            const label = card.querySelector("[data-point-reference-label]");

            if (!energyField || !label) {
                return;
            }

            label.textContent = energyField.value === "gaz" ? "PCE" : "PDL";
        };

        const refreshPointCards = () => {
            ensureAtLeastOneCard();
            const mode = getSiteMode();
            const cards = getCards();

            cards.forEach((card, index) => {
                const title = card.querySelector("[data-delivery-point-title]");
                const removeButton = card.querySelector("[data-remove-delivery-point]");
                const visible = mode === "multi" || index === 0;

                if (title) {
                    title.textContent = `Point de livraison ${index + 1}`;
                }

                card.hidden = !visible;
                setCardFieldsDisabled(card, !visible);
                syncPointReferenceLabel(card);

                if (removeButton) {
                    removeButton.hidden = cards.length <= 1 || mode !== "multi";
                }
            });

            if (addButton) {
                addButton.hidden = mode !== "multi";
            }

            if (modeCopy) {
                modeCopy.textContent = mode === "multi"
                    ? "Mode multi-site actif : vous pouvez ajouter plusieurs points de livraison."
                    : "Mode mono-site actif : une seule fiche point de livraison est ouverte.";
            }

            syncDeliveryPointEnergy();
        };

        const createCard = () => {
            if (!template || !template.content.firstElementChild) {
                return null;
            }

            return template.content.firstElementChild.cloneNode(true);
        };

        deliveryRoot.addEventListener("click", (event) => {
            const addTrigger = event.target.closest("[data-add-delivery-point]");
            if (addTrigger) {
                const newCard = createCard();
                if (!newCard) {
                    return;
                }

                const firstAddress = list.querySelector("[name='point_address']");
                const newAddress = newCard.querySelector("[name='point_address']");
                if (firstAddress && newAddress && firstAddress.value && !newAddress.value) {
                    newAddress.value = firstAddress.value;
                }

                const energyField = newCard.querySelector("[data-point-energy]");
                if (energyField && energySelect && (energySelect.value === "electricite" || energySelect.value === "gaz")) {
                    energyField.value = energySelect.value;
                }

                list.appendChild(newCard);
                refreshPointCards();
                return;
            }

            const removeTrigger = event.target.closest("[data-remove-delivery-point]");
            if (removeTrigger) {
                const card = removeTrigger.closest("[data-delivery-point-item]");
                if (!card) {
                    return;
                }

                card.remove();
                refreshPointCards();
            }
        });

        deliveryRoot.addEventListener("change", (event) => {
            if (event.target.matches("[data-site-mode-toggle]")) {
                refreshPointCards();
                return;
            }

            if (event.target.matches("[data-point-energy]")) {
                const card = event.target.closest("[data-delivery-point-item]");
                if (card) {
                    syncPointReferenceLabel(card);
                }
            }
        });

        syncDeliveryPointEnergy = () => {
            const mode = energySelect ? energySelect.value : "";
            const cards = getCards();

            cards.forEach((card) => {
                const wrapper = card.querySelector("[data-point-energy-wrap]");
                const select = card.querySelector("[data-point-energy]");

                if (!wrapper || !select) {
                    return;
                }

                const lockedEnergy = mode === "electricite" || mode === "gaz";
                wrapper.hidden = lockedEnergy;

                if (lockedEnergy) {
                    select.value = mode;
                } else if (!select.value) {
                    select.value = "electricite";
                }

                syncPointReferenceLabel(card);
            });
        };

        ensureAtLeastOneCard();
        refreshPointCards();
    }

    if (energySelect) {
        energySelect.addEventListener("change", syncEnergySections);
    }

    syncEnergySections();
}
