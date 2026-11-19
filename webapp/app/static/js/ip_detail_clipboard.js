/* IP detail controls also work on HTTP deployments without navigator.clipboard. */
(function () {
    async function writeText(value) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            try {
                await navigator.clipboard.writeText(value);
                return true;
            } catch {
                // Some browsers expose the API but deny clipboard permission.
            }
        }

        const previousFocus = document.activeElement;
        const input = document.createElement('textarea');
        input.value = value;
        input.readOnly = true;
        input.className = 'ip-clipboard-fallback';
        document.body.appendChild(input);
        try {
            input.select();
            return document.execCommand('copy');
        } finally {
            input.remove();
            if (previousFocus) previousFocus.focus();
        }
    }

    window.copyIpToClipboard = async function (value, button, description = value) {
        let copied = false;
        try {
            copied = await writeText(value);
        } catch {
            // Report failure through the control when both clipboard APIs fail.
        }
        if (!button) return;
        const message = copied ? 'Copied' : 'Copy failed';
        const feedback = button.querySelector('[data-copy-feedback]');
        button.classList.toggle('copied', copied);
        button.setAttribute('aria-label', `${message}: ${description}`);
        if (feedback) feedback.textContent = message;
        setTimeout(() => {
            button.classList.remove('copied');
            button.setAttribute('aria-label', `Copy ${description}`);
            if (feedback) feedback.textContent = `Copy ${description}`;
        }, 1500);
    };
})();
