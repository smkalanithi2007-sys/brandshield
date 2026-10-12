const analyzeForm = document.getElementById("analyze-form");

if (analyzeForm) {
  analyzeForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const nameInput = document.getElementById("brand-name");
    const domainInput = document.getElementById("brand-domain");
    const output = document.getElementById("analysis-result");
    const button = analyzeForm.querySelector("button");
    const brandName = nameInput.value.trim();

    if (!brandName) {
      output.textContent = "Enter a brand name first.";
      return;
    }

    button.disabled = true;
    button.textContent = "Checking live sources...";
    output.textContent = "Querying the configured providers...";

    try {
      const consent = document.getElementById("provider-consent").checked;
      const scan = await api.publicScan(
        brandName,
        domainInput.value.trim(),
        consent
      );
      output.replaceChildren();

      const heading = document.createElement("h3");
      heading.textContent =
        `One-time scan ${scan.scan_status}: ${scan.brand_name}`;
      output.appendChild(heading);
      const notSaved = document.createElement("p");
      notSaved.textContent =
        "This one-time scan is not saved to an account or scan history.";
      output.appendChild(notSaved);

      const providers = document.createElement("ul");
      scan.provider_results.forEach((provider) => {
        const item = document.createElement("li");
        item.textContent =
          `${provider.provider} — ${provider.status}: ${provider.message}`;
        providers.appendChild(item);
      });
      output.appendChild(providers);

      if (scan.findings.length === 0) {
        const empty = document.createElement("p");
        empty.textContent =
          "No matches were returned by the providers that completed. This does not prove the brand or domain is safe.";
        output.appendChild(empty);
      }

      scan.findings.forEach((finding) => {
        const card = document.createElement("article");
        const title = document.createElement("h4");
        title.textContent =
          `${finding.category}: ${finding.title} (${finding.severity})`;
        const detail = document.createElement("p");
        detail.textContent = `${finding.source} — ${finding.details}`;
        card.append(title, detail);

        if (finding.url) {
          const link = document.createElement("a");
          link.href = finding.url;
          link.target = "_blank";
          link.rel = "noopener noreferrer";
          link.textContent = "Review provider evidence";
          card.appendChild(link);
        }

        output.appendChild(card);
      });

      const disclaimer = document.createElement("p");
      disclaimer.className = "muted";
      disclaimer.textContent =
        "Search and catalog entries are unverified leads, not proof of fraud. Provider coverage can be incomplete.";
      output.appendChild(disclaimer);
    } catch (error) {
      output.replaceChildren();
      const message = document.createElement("p");
      message.textContent = error.status === 429
        ? "The one-time scan limit has been reached for this network. Try again later."
        : error.message;
      output.appendChild(message);
    } finally {
      button.disabled = false;
      button.textContent = "Scan without saving";
    }
  });
}
