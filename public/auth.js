// public/auth.js
(() => {
  const root = document.querySelector("[data-auth]");
  if (!root) return;

  const loginForm = root.querySelector("#login-form");
  const registerForm = root.querySelector("#register-form");
  const tabs = root.querySelectorAll(".auth-tab");
  const switches = root.querySelectorAll(".auth-link");

  if (!loginForm || !registerForm) return;

  const showPanel = (panel) => {
    const next = panel === "register" ? "register" : "login";

    loginForm.classList.toggle("active", next === "login");
    registerForm.classList.toggle("active", next === "register");

    tabs.forEach((tab) => {
      const isActive = tab.dataset.panel === next;
      tab.classList.toggle("primary", isActive);
      tab.classList.toggle("ghost", !isActive);
      tab.classList.toggle("active", isActive);
    });

    if (window.location.hash !== `#${next}`) {
      history.replaceState(null, "", `${window.location.pathname}#${next}`);
    }
  };

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => showPanel(tab.dataset.panel));
  });

  switches.forEach((btn) => {
    btn.addEventListener("click", () => showPanel(btn.dataset.panel));
  });

  const hash = (window.location.hash || "").replace("#", "");
  if (hash === "register" || hash === "login") {
    showPanel(hash);
  }
})();
