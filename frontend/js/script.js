
const analyzeForm = document.getElementById("analyze-form");

if (analyzeForm) {
  analyzeForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const input = document.getElementById("brand-name");
    const output = document.getElementById("analysis-result");
    const button = analyzeForm.querySelector("button");
    const brand = input.value.trim();

    if (!brand) {
      output.textContent = "Enter a brand name first.";
      return;
    }

    button.disabled = true;
    button.textContent = "Analyzing...";
    output.textContent = "Requesting demo analysis...";

    try {
      const data = await api.analyze(brand);
      output.replaceChildren();

      const heading = document.createElement("h3");
      heading.textContent = data.brand_name;

      const score = document.createElement("p");
      score.textContent =
        `Mock risk score: ${data.risk_score}/100 (${data.risk_level})`;

      const disclaimer = document.createElement("p");
      disclaimer.textContent = data.disclaimer;

      output.append(heading, score, disclaimer);
    } catch (error) {
      output.textContent = error.message;
    } finally {
      button.disabled = false;
      button.textContent = "Analyze Target →";
    }
  });
}