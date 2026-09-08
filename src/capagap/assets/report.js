(() => {
  "use strict";

  const select = (selector) => document.querySelector(selector);
  const search = select("input[data-search]");
  const state = select("[data-state-filter]");
  const count = select("[data-result-count]");
  const empty = select("[data-empty]");
  const reset = select("[data-reset]");
  const description = select("[data-group-description]");
  const buttons = [...document.querySelectorAll("[data-group-button]")];
  const records = [...document.querySelectorAll("[data-record]")].map((element) => ({
    element,
    group: element.dataset.group,
    state: element.dataset.state,
    name: element.dataset.name,
    text: element.dataset.search.toLocaleLowerCase(),
    toggle: element.querySelector(".row-toggle"),
    row: element.querySelector(".capability-row"),
    detail: element.querySelector(".details-row"),
  }));
  const labels = { comparable: "comparable", runtime: "runtime-only", excluded: "excluded" };
  let group = "comparable";
  let feedbackTimer;
  let copyTrigger;

  function setExpanded(record, expanded) {
    record.toggle.setAttribute("aria-expanded", String(expanded));
    record.detail.hidden = !expanded;
    record.row.classList.toggle("selected", expanded);
  }

  function openRecord(record) {
    records.forEach((entry) => setExpanded(entry, entry === record));
  }

  function update() {
    const terms = search.value.trim().toLocaleLowerCase().split(/\s+/).filter(Boolean);
    const inGroup = records.filter((record) => record.group === group);
    let visible = 0;
    records.forEach((record) => {
      const matches = record.group === group
        && (!state.value || record.state === state.value)
        && terms.every((term) => record.text.includes(term));
      record.element.hidden = !matches;
      if (matches) visible += 1;
    });
    const filtered = terms.length > 0 || Boolean(state.value);
    count.textContent = `${visible}${filtered ? ` of ${inGroup.length}` : ""} ${labels[group]} ${visible === 1 && !filtered ? "capability" : "capabilities"}`;
    empty.hidden = visible > 0;
    reset.hidden = !filtered;
    select("[data-empty-title]").textContent = filtered
      ? "No matching capabilities" : `No ${labels[group]} capabilities`;
    select("[data-empty-message]").textContent = filtered
      ? "Try another name, namespace, ATT&CK ID, API, string, process, address, or observation state."
      : group === "comparable"
        ? "Check the runtime-only and excluded views for other matches."
        : group === "runtime"
          ? "No additional capabilities were found only in the dynamic results."
          : "No findings were excluded from comparable coverage.";
    description.hidden = group === "comparable";
    description.textContent = group === "runtime"
      ? "Present in dynamic results but absent from comparable static findings. Not included in comparable coverage."
      : group === "excluded"
        ? "Unsupported dynamic scope or unverified rule source. Not included in comparable coverage."
        : "";
  }

  function switchGroup(next) {
    group = next;
    state.value = "";
    buttons.forEach((button) => {
      button.setAttribute("aria-pressed", String(button.dataset.groupButton === group));
    });
    const states = new Set(records.filter((record) => record.group === group).map((record) => record.state));
    [...state.options].forEach((option) => {
      option.hidden = Boolean(option.value) && !states.has(option.value);
      option.disabled = option.hidden;
    });
    update();
  }

  function notify(message) {
    const feedback = select("[data-feedback]");
    clearTimeout(feedbackTimer);
    feedback.textContent = message;
    feedback.hidden = false;
    feedbackTimer = setTimeout(() => { feedback.hidden = true; }, 3500);
  }

  records.forEach((record) => {
    record.toggle.addEventListener("click", () => {
      if (record.toggle.getAttribute("aria-expanded") === "true") setExpanded(record, false);
      else openRecord(record);
    });
    record.row.addEventListener("click", (event) => {
      if (event.target.closest("button, a, input, select, textarea") || String(window.getSelection())) return;
      record.toggle.click();
    });
    record.toggle.addEventListener("keydown", (event) => {
      const visible = records.filter((entry) => !entry.element.hidden);
      const index = visible.indexOf(record);
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        const next = index + (event.key === "ArrowDown" ? 1 : -1);
        visible[Math.max(0, Math.min(next, visible.length - 1))]?.toggle.focus();
      } else if (event.key === "ArrowRight") {
        event.preventDefault();
        openRecord(record);
      } else if (event.key === "ArrowLeft" || event.key === "Escape") {
        event.preventDefault();
        setExpanded(record, false);
      }
    });
    record.detail.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setExpanded(record, false);
        record.toggle.focus();
      }
    });
  });

  buttons.forEach((button) => button.addEventListener("click", () => switchGroup(button.dataset.groupButton)));
  search.addEventListener("input", update);
  state.addEventListener("change", update);
  reset.addEventListener("click", () => {
    search.value = "";
    state.value = "";
    update();
    search.focus();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "/" && !event.ctrlKey && !event.metaKey && !event.altKey
        && !event.target.closest("input, textarea, select, [contenteditable]")
        && !select(".copy-dialog").open) {
      event.preventDefault();
      search.focus();
    }
  });

  document.querySelectorAll("[data-open-section]").forEach((link) => {
    link.addEventListener("click", () => {
      const section = document.getElementById(link.hash.slice(1));
      if (!section) return;
      section.open = true;
      requestAnimationFrame(() => section.querySelector("summary").focus({ preventScroll: true }));
    });
  });
  document.querySelectorAll("[data-find]").forEach((button) => {
    button.addEventListener("click", () => {
      const record = records.find((entry) => entry.name === button.dataset.find);
      if (!record) return;
      search.value = "";
      switchGroup(record.group);
      openRecord(record);
      record.toggle.focus({ preventScroll: true });
      record.row.scrollIntoView({ block: "center" });
    });
  });

  const dialog = select(".copy-dialog");
  dialog.addEventListener("close", () => copyTrigger?.focus({ preventScroll: true }));
  dialog.addEventListener("click", (event) => {
    if (event.target !== dialog) return;
    const bounds = dialog.getBoundingClientRect();
    if (event.clientX < bounds.left || event.clientX > bounds.right
        || event.clientY < bounds.top || event.clientY > bounds.bottom) dialog.close();
  });
  document.querySelectorAll("[data-copy]").forEach((button) => {
    button.addEventListener("click", async () => {
      const value = button.dataset.copy;
      try {
        await navigator.clipboard.writeText(value);
        notify("Copied to clipboard");
      } catch {
        copyTrigger = button;
        const text = dialog.querySelector("textarea");
        text.value = value;
        dialog.showModal();
        text.focus();
        text.select();
      }
    });
  });

  select("[data-export]").addEventListener("click", () => {
    try {
      const data = JSON.parse(select("#report-data").textContent);
      const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2) + "\n"], { type: "application/json" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = data.runs ? "capagap-matrix.json" : "capagap-comparison.json";
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      notify("JSON export prepared");
    } catch {
      notify("Could not prepare JSON export. Generate JSON with the command-line tool.");
    }
  });

  let printState = [];
  window.addEventListener("beforeprint", () => {
    printState = [...document.querySelectorAll("details")].map((element) => [element, element.open]);
    printState.forEach(([element]) => { element.open = true; });
  });
  window.addEventListener("afterprint", () => {
    printState.forEach(([element, open]) => { element.open = open; });
    printState = [];
  });

  switchGroup("comparable");
})();
