const profileMenu = document.querySelector('.profile-menu');

if (profileMenu) {
  const trigger = profileMenu.querySelector('.profile-trigger');
  const dropdown = profileMenu.querySelector('.profile-dropdown');

  const closeMenu = () => {
    profileMenu.classList.remove('is-open');
    trigger.setAttribute('aria-expanded', 'false');
  };

  trigger.setAttribute('aria-expanded', 'false');
  trigger.setAttribute('aria-haspopup', 'true');

  trigger.addEventListener('click', (event) => {
    event.stopPropagation();
    const isOpen = profileMenu.classList.toggle('is-open');
    trigger.setAttribute('aria-expanded', String(isOpen));
  });

  document.addEventListener('click', (event) => {
    if (!profileMenu.contains(event.target)) {
      closeMenu();
    }
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      closeMenu();
      trigger.focus();
    }
  });

  if (dropdown) {
    dropdown.addEventListener('click', (event) => {
      event.stopPropagation();
    });
  }
}
