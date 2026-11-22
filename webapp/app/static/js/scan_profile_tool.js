(function () {
  function init() {
    const tool = document.querySelector('select[name="scan_tool"]');
    if (!tool) return;

    const toolOptions = {
      nmap: ["nses", "nmap_additional_params"],
      masscan: ["detect_protocol"]
    };

    function updateFields() {
      const warning = document.querySelector('[data-masscan-banner-warning]');
      if (warning) {
        warning.hidden = tool.value !== "masscan" || !tool.form.elements.namedItem("detect_protocol").checked;
      }
      for (const [scanner, fields] of Object.entries(toolOptions)) {
        const active = tool.value === scanner;
        for (const name of fields) {
          const field = tool.form.elements.namedItem(name);
          if (!field) continue;
          field.closest("tr").hidden = !active;
          field.disabled = !active;
        }
      }
    }

    const $ = window.jQuery;
    if ($?.fn?.select2) {
      $(tool.form).find(".plum-select2-remote").each(function () {
        const field = $(this);
        field.select2({
          theme: "bootstrap",
          width: "100%",
          placeholder: field.data("placeholder") || "Select Value",
          allowClear: true,
          minimumInputLength: 1,
          ajax: {
            url: field.data("remote-url"),
            dataType: "json",
            delay: 250,
            data: (params) => ({q: params.term || "", limit: 30}),
            processResults: (data) => ({results: data}),
            cache: true
          }
        });
      });
    }

    if ($) $(tool).on("change", updateFields);
    else tool.addEventListener("change", updateFields);
    tool.form.elements.namedItem("detect_protocol").addEventListener("change", updateFields);
    updateFields();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
