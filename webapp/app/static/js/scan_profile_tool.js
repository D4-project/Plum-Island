(function () {
  function initSearchDraft(form) {
    const query = form.elements.namedItem("search_query");
    const applyToAll = form.elements.namedItem("apply_to_all");
    const status = document.querySelector("[data-profile-filter-status]");
    const save = form.querySelector('button[type="submit"]');
    if (!query || !applyToAll || !status || !save) return;

    const oldId = query.id;
    query.id = "query";
    query.dataset.queryAutocomplete = "true";
    query.dataset.queryAutocompleteDisallowed = "port";
    const label = form.querySelector(`label[for="${oldId}"]`);
    if (label) label.htmlFor = "query";
    const wrapper = document.createElement("div");
    wrapper.className = "search-query-wrapper";
    query.parentNode.insertBefore(wrapper, query);
    wrapper.appendChild(query);
    const menu = document.createElement("div");
    menu.id = "query-tag-suggest";
    menu.className = "tag-suggest-menu";
    menu.setAttribute("role", "listbox");
    menu.setAttribute("aria-label", "Search suggestions");
    wrapper.appendChild(menu);
    if (typeof bindQueryTagHelper === "function") bindQueryTagHelper();

    const preview = document.querySelector("[data-profile-filter-preview]");
    if (preview) {
      wrapper.after(preview);
      const button = preview.querySelector("button");
      const result = preview.querySelector("[role=status]");
      let controller;

      query.addEventListener("input", () => {
        controller?.abort();
        result.textContent = "";
      });
      button.addEventListener("click", async () => {
        const draft = query.value.trim();
        if (!draft) return;
        controller = new AbortController();
        const request = controller;
        const url = new URL(preview.dataset.endpoint, location.href);
        url.searchParams.set("q", draft);
        button.disabled = true;
        result.textContent = "Checking targets…";
        try {
          const response = await fetch(url, {cache: "no-store", signal: request.signal});
          if (response.redirected) throw new Error();
          const data = await response.json();
          if (request.signal.aborted) return;
          result.textContent = data.error || (data.candidates.length
            ? data.candidates.map(([host, port]) => `${host.includes(":") ? `[${host}]` : host}:${port}`).join(", ")
            : "This filter returned no scan candidates.");
        } catch (_error) {
          if (!request.signal.aborted) result.textContent = "Unable to check targets.";
        } finally {
          if (controller === request) button.disabled = false;
        }
      });
    }

    function updateField() {
      query.disabled = applyToAll.checked;
      if (preview) preview.hidden = query.disabled;
    }

    save.after(status);
    applyToAll.addEventListener("change", updateField);
    updateField();

    form.addEventListener("submit", (event) => {
      if (!status.hidden) {
        event.preventDefault();
        return;
      }
      if (event.defaultPrevented || query.disabled || !query.value.trim()) return;
      status.hidden = false;
      save.disabled = true;
    });

    window.addEventListener("pageshow", () => {
      if (!status.hidden) save.disabled = false;
      status.hidden = true;
      updateField();
    });
  }

  function init() {
    const tool = document.querySelector('select[name="scan_tool"]');
    if (!tool) return;
    initSearchDraft(tool.form);

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
