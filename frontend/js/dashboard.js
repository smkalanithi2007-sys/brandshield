async function loadDashboard() {
  const targets = document.getElementById("total-brands");
  const total = document.getElementById("total-threats");
  const open = document.getElementById("open-threats");
  const list = document.getElementById("recent-threats");

  try {
    const [brandsData, report, findingsData] = await Promise.all([
      api.brands(),
      api.reports(),
      api.findings()
    ]);

    if (targets) targets.textContent = brandsData.items.length;
    if (total) total.textContent = report.total_findings;
    if (open) open.textContent = report.unresolved_findings;

    if (list) {
      list.replaceChildren();
      const recent = findingsData.items.slice(0, 5);
      if (recent.length === 0) {
        list.textContent = "No findings recorded yet. Add a brand and run a scan.";
      }

      recent.forEach((finding) => {
        const item = document.createElement("p");
        item.textContent =
          `${finding.brand_id ? "Monitored brand" : finding.title} — ` +
          `${finding.category} (${finding.severity}, ${finding.status})`;
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
