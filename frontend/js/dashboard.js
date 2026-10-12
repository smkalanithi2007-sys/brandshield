
async function loadDashboard() {
  const targets = document.getElementById("total-brands");
  const total = document.getElementById("total-threats");
  const open = document.getElementById("open-threats");
  const list = document.getElementById("recent-threats");

  try {
    const [brandsData, threatsData, reportsData] = await Promise.all([
      api.brands(),
      api.threats(),
      api.reports()
    ]);

    if (targets) targets.textContent = brandsData.items.length;
    if (total) total.textContent = reportsData.total_findings;
    if (open) open.textContent = reportsData.unresolved_findings;

    if (list) {
      list.replaceChildren();

      if (threatsData.items.length === 0) {
        list.textContent = "No saved demo findings yet.";
      }

      threatsData.items.slice(0, 5).forEach((threat) => {
        const item = document.createElement("p");
        item.textContent =
          `${threat.brand_name} — ${threat.type} (${threat.status})`;
        list.appendChild(item);
      });
    }
  } catch (error) {
    if (list) list.textContent = `Could not load dashboard: ${error.message}`;
  }
}

if (document.getElementById("dashboard-page")) {
  loadDashboard();
}