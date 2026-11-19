(function () {
  'use strict';
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
