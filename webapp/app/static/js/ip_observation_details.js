document.addEventListener("toggle", async (event) => {
    const detail = event.target;
    if (!detail.matches?.("[data-observation-details]") || !detail.open || detail.dataset.state) return;
    const content = detail.querySelector("[data-observation-detail-content]");
    detail.dataset.state = "loading";
    content.textContent = "Loading observation…";
    try {
        const response = await fetch(detail.dataset.observationDetails, {cache: "no-store"});
        if (!response.ok || response.redirected) throw new Error("Unavailable");
        const fragment = new DOMParser().parseFromString(await response.text(), "text/html")
            .querySelector("[data-observation-detail-fragment]");
        if (!fragment) throw new Error("Invalid observation");
        content.replaceChildren(document.importNode(fragment, true));
        detail.dataset.state = "loaded";
    } catch (_error) {
        content.textContent = "Unable to load this observation. Reopen to retry.";
        delete detail.dataset.state;
    }
}, true);
