(function (global) {
    'use strict';

    function showFailure(code) {
        const messages = {
            authentication: 'CIRCL rejected the Passive DNS credentials. Check the username and password in Plum Settings.',
            timeout: 'CIRCL Passive DNS did not respond in time. Try again later.',
            invalid_response: 'CIRCL Passive DNS returned an invalid response. Try again later.',
            upstream: 'CIRCL Passive DNS is unavailable. Try again later.'
        };
        let modal = document.getElementById('plum-pdns-failure-modal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'plum-pdns-failure-modal';
            modal.className = 'modal fade';
            modal.tabIndex = -1;
            modal.setAttribute('role', 'dialog');
            modal.setAttribute('aria-labelledby', 'plum-pdns-failure-title');
            modal.innerHTML = '<div class="modal-dialog" role="document"><div class="modal-content">'
                + '<div class="modal-header"><button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>'
                + '<h4 class="modal-title" id="plum-pdns-failure-title"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> Passive DNS lookup failed</h4></div>'
                + '<div class="modal-body"><p id="plum-pdns-failure-message" role="alert"></p></div>'
                + '<div class="modal-footer"><button type="button" class="btn btn-primary" data-dismiss="modal">Close</button></div>'
                + '</div></div>';
            document.body.appendChild(modal);
        }
        modal.querySelector('#plum-pdns-failure-message').textContent = messages[code] || messages.upstream;
        if (global.jQuery && global.jQuery.fn.modal) {
            global.jQuery(modal).modal('show');
        }
    }

    global.PlumPdnsStatus = {showFailure};
}(window));
