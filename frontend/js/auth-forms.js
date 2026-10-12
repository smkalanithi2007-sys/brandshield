const authForm = document.querySelector("[data-auth-form]");

if (authForm) {
  authForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const message = document.getElementById("message");
    const button = authForm.querySelector("button");
    const mode = authForm.dataset.authForm;
    button.disabled = true;
    message.textContent = mode === "register"
      ? "Creating your account..."
      : "Signing in...";

    try {
      await api[mode](
        document.getElementById("email").value.trim(),
        document.getElementById("password").value
      );

      const requestedPage = new URLSearchParams(location.search).get("next");
      const nextPage = requestedPage && !requestedPage.startsWith("//")
        && !requestedPage.includes(":")
        ? requestedPage
        : "dashboard.html";
      location.replace(nextPage);
    } catch (error) {
      message.textContent = error.message;
      button.disabled = false;
    }
  });
}
