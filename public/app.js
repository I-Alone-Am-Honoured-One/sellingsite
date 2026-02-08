// Profile menu dropdown handling
document.addEventListener('DOMContentLoaded', () => {
  const siteLoader = document.querySelector('.site-loader');
  if (siteLoader) {
    const introShown = sessionStorage.getItem('sellar_intro_shown') === 'true';
    if (introShown) {
      siteLoader.remove();
    } else {
      sessionStorage.setItem('sellar_intro_shown', 'true');
      const hideIntro = () => {
        siteLoader.classList.add('is-hidden');
        siteLoader.addEventListener('transitionend', () => {
          siteLoader.remove();
        }, { once: true });

        setTimeout(() => {
          if (siteLoader.isConnected) {
            siteLoader.remove();
          }
        }, 1400);
      };

      window.addEventListener('load', hideIntro, { once: true });
      setTimeout(hideIntro, 2200);
    }
  }

  // Desktop profile menu
  const profileMenus = document.querySelectorAll('.profile-menu');
  profileMenus.forEach(menu => {
    const trigger = menu.querySelector('.profile-trigger');
    if (trigger) {
      trigger.addEventListener('click', (e) => {
        e.stopPropagation();
        menu.classList.toggle('is-open');
      });
    }
  });

  // Mobile profile menu
  const mobileMenus = document.querySelectorAll('.profile-menu-mobile');
  mobileMenus.forEach(menu => {
    const trigger = menu.querySelector('.profile-trigger-mobile');
    if (trigger) {
      trigger.addEventListener('click', (e) => {
        e.stopPropagation();
        menu.classList.toggle('is-open');
      });
    }
  });

  // Close menus when clicking outside
  document.addEventListener('click', (e) => {
    profileMenus.forEach(menu => {
      if (!menu.contains(e.target)) {
        menu.classList.remove('is-open');
      }
    });
    mobileMenus.forEach(menu => {
      if (!menu.contains(e.target)) {
        menu.classList.remove('is-open');
      }
    });
  });

  // Close menus on escape key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      profileMenus.forEach(menu => menu.classList.remove('is-open'));
      mobileMenus.forEach(menu => menu.classList.remove('is-open'));
    }
  });

  // Image preview for file uploads
  const fileInputs = document.querySelectorAll('input[type="file"]');
  fileInputs.forEach(input => {
    input.addEventListener('change', (e) => {
      if (input.name === 'avatar') {
        const clearAvatarInput = document.querySelector('input[name="clear_avatar"]');
        if (clearAvatarInput) {
          clearAvatarInput.value = 'false';
        }
      }
      if (input.name === 'background') {
        const clearBackgroundInput = document.querySelector('input[name="clear_background"]');
        if (clearBackgroundInput) {
          clearBackgroundInput.value = 'false';
        }
      }
      const file = e.target.files[0];
      if (file && file.type.startsWith('image/')) {
        const reader = new FileReader();
        reader.onload = (event) => {
          // Find or create preview element
          let preview = input.parentElement.querySelector('.image-preview');
          if (!preview) {
            preview = document.createElement('div');
            preview.className = 'image-preview';
            input.parentElement.appendChild(preview);
          }
          preview.innerHTML = `<img src="${event.target.result}" alt="Preview" style="max-width: 200px; max-height: 200px; border-radius: 0.75rem; margin-top: 1rem; box-shadow: var(--shadow-md);">`;
        };
        reader.readAsDataURL(file);
      }
    });
  });

  const profilePreview = document.querySelector('.profile-header-section.profile-preview');
  if (profilePreview) {
    const previewInitial = profilePreview.dataset.initial || '';
    const banner = profilePreview.querySelector('.profile-banner');
    const avatarContainer = profilePreview.querySelector('.profile-avatar-large');
    const clearButtons = profilePreview.querySelectorAll('.preview-clear');
    const avatarInput = document.querySelector('input[name="avatar"]');
    const backgroundInput = document.querySelector('input[name="background"]');
    const backgroundColorInput = document.querySelector('input[name="profile_background_color"]');
    const clearAvatarInput = document.querySelector('input[name="clear_avatar"]');
    const clearBackgroundInput = document.querySelector('input[name="clear_background"]');

    clearButtons.forEach(button => {
      button.addEventListener('click', () => {
        const type = button.dataset.clear;
        if (type === 'avatar') {
          if (clearAvatarInput) {
            clearAvatarInput.value = 'true';
          }
          if (avatarInput) {
            avatarInput.value = '';
          }
          const existingImage = avatarContainer?.querySelector('img');
          if (existingImage) {
            existingImage.remove();
          }
          if (avatarContainer && !avatarContainer.querySelector('span')) {
            const initialSpan = document.createElement('span');
            initialSpan.textContent = previewInitial || '?';
            avatarContainer.prepend(initialSpan);
          }
        }

        if (type === 'background') {
          if (clearBackgroundInput) {
            clearBackgroundInput.value = 'true';
          }
          if (backgroundInput) {
            backgroundInput.value = '';
          }
          if (backgroundColorInput) {
            backgroundColorInput.value = '';
          }
          if (banner) {
            banner.removeAttribute('style');
          }
        }
      });
    });

    if (backgroundColorInput) {
      backgroundColorInput.addEventListener('input', () => {
        if (clearBackgroundInput) {
          clearBackgroundInput.value = 'false';
        }
      });
    }
  }

  // Auto-resize textareas
  const textareas = document.querySelectorAll('textarea');
  textareas.forEach(textarea => {
    textarea.addEventListener('input', () => {
      textarea.style.height = 'auto';
      const styles = window.getComputedStyle(textarea);
      const maxHeight = parseFloat(styles.maxHeight);
      if (!Number.isNaN(maxHeight) && maxHeight > 0 && textarea.scrollHeight > maxHeight) {
        textarea.style.height = `${maxHeight}px`;
        textarea.style.overflowY = 'auto';
      } else {
        textarea.style.height = `${textarea.scrollHeight}px`;
        textarea.style.overflowY = 'hidden';
      }
    });
  });

  // Scroll to bottom of message threads
  const threadMessages = document.querySelector('.thread-messages');
  if (threadMessages) {
    threadMessages.scrollTop = threadMessages.scrollHeight;
  }

  // Real-time form validation
  const forms = document.querySelectorAll('form');
  forms.forEach(form => {
    const inputs = form.querySelectorAll('input[required], textarea[required], select[required]');
    inputs.forEach(input => {
      input.addEventListener('blur', () => {
        if (!input.value.trim()) {
          input.style.borderColor = 'var(--error)';
        } else {
          input.style.borderColor = '';
        }
      });
      
      input.addEventListener('input', () => {
        if (input.value.trim()) {
          input.style.borderColor = '';
        }
      });
    });
  });

  // Price input formatting
  const priceInputs = document.querySelectorAll('input[name="price"]');
  priceInputs.forEach(input => {
    input.addEventListener('blur', () => {
      const value = parseFloat(input.value);
      if (!isNaN(value)) {
        input.value = value.toFixed(2);
      }
    });
  });

  // Confirm before deleting
  const deleteButtons = document.querySelectorAll('button[formaction*="delete"], form[action*="delete"] button[type="submit"]');
  deleteButtons.forEach(button => {
    button.addEventListener('click', (e) => {
      if (!confirm('Are you sure you want to delete this? This action cannot be undone.')) {
        e.preventDefault();
      }
    });
  });

  // Auto-dismiss alerts after 5 seconds
  const alerts = document.querySelectorAll('.success, .error');
  alerts.forEach(alert => {
    setTimeout(() => {
      alert.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
      alert.style.opacity = '0';
      alert.style.transform = 'translateY(-10px)';
      setTimeout(() => {
        alert.remove();
      }, 300);
    }, 5000);
  });

  // Add loading state to buttons on form submit
  forms.forEach(form => {
    form.addEventListener('submit', (e) => {
      const submitButton = form.querySelector('button[type="submit"]');
      if (submitButton && !submitButton.disabled) {
        submitButton.disabled = true;
        const originalText = submitButton.textContent;
        submitButton.textContent = 'Loading...';
        submitButton.style.opacity = '0.7';
        
        // Re-enable after 3 seconds as a fallback
        setTimeout(() => {
          submitButton.disabled = false;
          submitButton.textContent = originalText;
          submitButton.style.opacity = '1';
        }, 3000);
      }
    });
  });

  // Smooth scroll for anchor links
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
      e.preventDefault();
      const target = document.querySelector(this.getAttribute('href'));
      if (target) {
        target.scrollIntoView({
          behavior: 'smooth',
          block: 'start'
        });
      }
    });
  });

  // Add touch feedback for mobile
  if ('ontouchstart' in window) {
    const touchables = document.querySelectorAll('button, a, .card, .listing-card-mini');
    touchables.forEach(element => {
      element.addEventListener('touchstart', () => {
        element.style.opacity = '0.8';
      });
      element.addEventListener('touchend', () => {
        element.style.opacity = '1';
      });
    });
  }

  // Prevent double-click spam
  const clickableElements = document.querySelectorAll('button, a');
  clickableElements.forEach(element => {
    let clickTimeout;
    element.addEventListener('click', () => {
      if (clickTimeout) {
        return;
      }
      clickTimeout = setTimeout(() => {
        clickTimeout = null;
      }, 300);
    });
  });
});
