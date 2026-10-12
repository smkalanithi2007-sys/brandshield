async function requireAuth() {
  try {
    const { user } = await api.me();
    const email = document.getElementById("user-email");
    if (email) email.textContent = user.email;
    return user;
  } catch (error) {
    if (error.status === 401) {
      const next = encodeURIComponent(
        `${location.pathname}${location.search}${location.hash}`
      );
      location.replace(`login.html?next=${next}`);
      return null;
    }

    const message = document.getElementById("auth-message");
    if (message) message.textContent = error.message;
    throw error;
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  if (document.body.dataset.authRequired !== "true") return;

  try {
    const user = await requireAuth();
    if (!user) return;

    const signOut = document.getElementById("sign-out");
    if (signOut) {
      signOut.addEventListener("click", async () => {
        signOut.disabled = true;
        try {
          await api.logout();
          location.replace("index.html");
        } catch (error) {
          const message = document.getElementById("auth-message");
          if (message) message.textContent = error.message;
          signOut.disabled = false;
        }
      });
    }
  } catch {
    document.querySelector("main")?.setAttribute("aria-busy", "true");
  }
});
