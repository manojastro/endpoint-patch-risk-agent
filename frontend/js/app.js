// App bootstrap: meta badges, tab navigation, view rendering.
import { api } from "./api.js";
import { clear, el } from "./ui.js";
import * as overview from "./views/overview.js";
import * as catalog from "./views/catalog.js";
import * as campaigns from "./views/campaigns.js";
import * as ops from "./views/ops.js";

const VIEWS = {
  overview: { render: overview.render, refreshable: false },
  catalog: { render: catalog.render, refreshable: false },
  campaigns: { render: campaigns.render, refreshable: true },
  ops: { render: ops.render, refreshable: false },
};

let current = "overview";

async function loadMeta() {
  try {
    const meta = await api.meta();
    const mock = document.getElementById("mock-badge");
    if (meta.mock_mode) mock.classList.remove("hidden");
    const estate = document.getElementById("estate-badge");
    estate.textContent = `ESTATE ${meta.estate_size} - SEED ${meta.sim_seed}`;
    estate.classList.remove("hidden");
    document.title = `${meta.app_name} v${meta.version}`;
  } catch { /* server unreachable; leave badges hidden */ }
}

function activate(view) {
  current = view;
  for (const tab of document.querySelectorAll(".tab"))
    tab.classList.toggle("active", tab.dataset.view === view);
  for (const section of document.querySelectorAll(".view"))
    section.classList.toggle("active", section.id === "view-" + view);
  const root = document.getElementById("view-" + view);
  clear(root);
  VIEWS[view].render(root);
}

function boot() {
  for (const tab of document.querySelectorAll(".tab")) {
    tab.addEventListener("click", () => activate(tab.dataset.view));
  }
  loadMeta();
  activate("overview");
  // Periodic auto-refresh of the overview KPIs (cheap reads).
  setInterval(() => {
    if (current === "overview" && !document.hidden) {
      overview.render(document.getElementById("view-overview"));
    }
  }, 15000);
}

boot();
