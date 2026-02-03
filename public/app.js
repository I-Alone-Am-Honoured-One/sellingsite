const profileMenu = document.querySelector('.profile-menu');
const mobileQuery = window.matchMedia('(max-width: 768px)');

const syncDeviceClass = (event) => {
  const isMobile = event.matches;
  document.body.classList.toggle('is-mobile', isMobile);
  document.body.dataset.device = isMobile ? 'mobile' : 'desktop';
};

syncDeviceClass(mobileQuery);
mobileQuery.addEventListener('change', syncDeviceClass);

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
    if (profileMenu.classList.contains('is-open')) {
      window.location.href = '/profile';
      return;
    }
    profileMenu.classList.add('is-open');
    trigger.setAttribute('aria-expanded', 'true');
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
