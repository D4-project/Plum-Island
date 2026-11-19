(function () {
  'use strict';
  document.querySelectorAll('[data-prefilled-default]').forEach(function (marker) {
    const input = document.getElementById(marker.dataset.prefilledDefault);
    function markEdited() {
      marker.value = 'false';
    }
    input.addEventListener('input', markEdited);
    input.addEventListener('change', markEdited);
  });
  document.querySelectorAll('[data-secret-field]').forEach(function (field) {
    const action = field.querySelector('[data-secret-action]');
    const input = field.querySelector('[data-secret-value]');
    function update() {
      const replacing = action.value === 'replace';
      input.disabled = !replacing;
      input.required = replacing;
      input.hidden = !replacing;
      if (!replacing) input.value = '';
    }
    action.addEventListener('change', update);
    update();
  });
}());
