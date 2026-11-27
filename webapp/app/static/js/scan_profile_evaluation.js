for (const status of document.querySelectorAll("[data-target-evaluation]")) {
    async function update() {
        if (!status.isConnected) return;
        try {
            if (!document.hidden) {
                const response = await fetch(status.dataset.targetEvaluation, {cache: "no-store"});
                if (response.ok && !response.redirected) {
                    const data = await response.json();
                    if (!data.evaluating) {
                        status.textContent = "Target evaluation finished";
                        return;
                    }
                    status.textContent = `${data.checked.toLocaleString()} observations checked · ${data.retained.toLocaleString()} targets retained`;
                }
            }
        } catch (_error) {
            // Hold the last counts while the backend is unavailable.
        }
        setTimeout(update, 3000);
    }
    update();
}
