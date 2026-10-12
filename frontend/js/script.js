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
      const scan = await api.scan(
        brandName,
        domainInput.value.trim(),
        consent
      );
      output.replaceChildren();

      const heading = document.createElement("h3");
      heading.textContent = `Scan ${scan.scan_status}: ${scan.brand_name}`;
      output.appendChild(heading);

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
      message.textContent = error.status === 401
        ? "Sign in or create an account to run a scan."
        : error.message;
      output.appendChild(message);
      if (error.status === 401) {
        const link = document.createElement("a");
        link.href = "login.html";
        link.textContent = "Sign in or create an account";
        output.appendChild(link);
      }
    } finally {
      button.disabled = false;
      button.textContent = "Run live scan";
    }
  });
}
