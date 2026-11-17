(function () {
    'use strict';
    const button = document.getElementById('plum-welcome-button');
    const moo = document.getElementById('plum-welcome-moo');
    if (!button || !moo) return;

    button.addEventListener('click', function () {
        moo.currentTime = 0;
        const playback = moo.play();
        if (playback) playback.catch(function () {
            // A browser can deny playback; the next click can try again.
        });
    });
})();
