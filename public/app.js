// Profile menu dropdown handling
document.addEventListener('DOMContentLoaded', () => {
  const siteLoader = document.querySelector('.site-loader');
  if (siteLoader) {
    window.addEventListener('load', () => {
      siteLoader.classList.add('is-hidden');
      siteLoader.addEventListener('transitionend', () => {
        siteLoader.remove();
      }, { once: true });

      setTimeout(() => {
        if (siteLoader.isConnected) {
          siteLoader.remove();
        }
      }, 1200);
    }, { once: true });
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

  const createCropModal = () => {
    const modal = document.createElement('div');
    modal.className = 'image-crop-modal';
    modal.hidden = true;
    modal.innerHTML = `
      <div class="image-crop-panel" role="dialog" aria-modal="true" aria-label="Crop image">
        <div class="image-crop-header">
          <h3>Adjust image</h3>
          <button type="button" class="button ghost small image-crop-cancel">Cancel</button>
        </div>
        <div class="image-crop-frame">
          <img class="image-crop-image" alt="Crop preview" />
          <div class="image-crop-grid"></div>
        </div>
        <div class="image-crop-controls">
          <label>
            Zoom
            <input type="range" min="1" max="3" step="0.01" value="1" class="image-crop-zoom" />
          </label>
        </div>
        <div class="image-crop-actions">
          <button type="button" class="button ghost image-crop-reset">Reset</button>
          <button type="button" class="button primary image-crop-confirm">Use image</button>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
    return modal;
  };

  const cropModal = createCropModal();
  const cropImage = cropModal.querySelector('.image-crop-image');
  const cropFrame = cropModal.querySelector('.image-crop-frame');
  const cropZoom = cropModal.querySelector('.image-crop-zoom');
  const cropReset = cropModal.querySelector('.image-crop-reset');
  const cropCancel = cropModal.querySelector('.image-crop-cancel');
  const cropConfirm = cropModal.querySelector('.image-crop-confirm');

  const parseAspect = (value) => {
    if (!value) return null;
    if (value.includes('/')) {
      const [num, den] = value.split('/').map(part => Number(part));
      if (!Number.isNaN(num) && !Number.isNaN(den) && den !== 0) {
        return num / den;
      }
    }
    const parsed = Number(value);
    return Number.isNaN(parsed) || parsed <= 0 ? null : parsed;
  };

  const setPreviewImage = (input, previewUrl) => {
    let preview = input.parentElement.querySelector('.image-preview');
    if (!preview) {
      preview = document.createElement('div');
      preview.className = 'image-preview';
      input.parentElement.appendChild(preview);
    }
    preview.innerHTML = `<img src="${previewUrl}" alt="Preview" style="max-width: 200px; max-height: 200px; border-radius: 0.75rem; margin-top: 1rem; box-shadow: var(--shadow-md);">`;
  };

  const setProfilePreviewImage = (input, previewUrl) => {
    const profilePreview = document.querySelector('.profile-header-section.profile-preview');
    if (!profilePreview) return;
    const banner = profilePreview.querySelector('.profile-banner');
    const avatarContainer = profilePreview.querySelector('.profile-avatar-large');

    if (input.name === 'background' && banner) {
      banner.style.backgroundImage = `url('${previewUrl}')`;
      banner.style.backgroundSize = 'cover';
      banner.style.backgroundPosition = 'center';
    }

    if (input.name === 'avatar' && avatarContainer) {
      const existingImage = avatarContainer.querySelector('img');
      const initial = avatarContainer.querySelector('span');
      if (initial) {
        initial.remove();
      }
      if (existingImage) {
        existingImage.src = previewUrl;
      } else {
        const image = document.createElement('img');
        image.src = previewUrl;
        image.alt = 'Avatar preview';
        avatarContainer.prepend(image);
      }
    }
  };

  const applyFileToInput = (input, file) => {
    const transfer = new DataTransfer();
    transfer.items.add(file);
    input.files = transfer.files;
  };

  let activeCrop = null;

  const closeCropper = () => {
    cropModal.hidden = true;
    cropImage.src = '';
    cropImage.style.transform = '';
    cropImage.classList.remove('is-dragging');
    activeCrop = null;
  };

  const openCropper = (file, input, aspect) => {
    const reader = new FileReader();
    reader.onload = () => {
      const previewUrl = reader.result;
      cropImage.src = previewUrl;
      cropModal.hidden = false;

      const frameWidth = cropFrame.clientWidth;
      const frameHeight = frameWidth / aspect;
      cropFrame.style.height = `${frameHeight}px`;

      const state = {
        file,
        input,
        aspect,
        previewUrl,
        zoom: 1,
        translateX: 0,
        translateY: 0,
        baseScale: 1,
        displayWidth: 0,
        displayHeight: 0,
        originalWidth: 0,
        originalHeight: 0
      };
      activeCrop = state;

      const imageEl = new Image();
      imageEl.onload = () => {
        const baseScale = Math.max(frameWidth / imageEl.width, frameHeight / imageEl.height);
        state.originalWidth = imageEl.width;
        state.originalHeight = imageEl.height;
        state.baseScale = baseScale;
        state.displayWidth = imageEl.width * baseScale;
        state.displayHeight = imageEl.height * baseScale;
        state.translateX = (frameWidth - state.displayWidth) / 2;
        state.translateY = (frameHeight - state.displayHeight) / 2;
        cropZoom.value = '1';
        updateCropTransform();
      };
      imageEl.src = previewUrl;
    };
    reader.readAsDataURL(file);
  };

  const clamp = (value, min, max) => Math.min(Math.max(value, min), max);

  const updateCropTransform = () => {
    if (!activeCrop) return;
    const { baseScale, zoom } = activeCrop;
    const scale = baseScale * zoom;
    const frameWidth = cropFrame.clientWidth;
    const frameHeight = cropFrame.clientHeight;
    const displayWidth = activeCrop.originalWidth * scale;
    const displayHeight = activeCrop.originalHeight * scale;
    activeCrop.displayWidth = displayWidth;
    activeCrop.displayHeight = displayHeight;

    const minX = frameWidth - displayWidth;
    const minY = frameHeight - displayHeight;
    activeCrop.translateX = clamp(activeCrop.translateX, minX, 0);
    activeCrop.translateY = clamp(activeCrop.translateY, minY, 0);

    cropImage.style.transform = `translate(${activeCrop.translateX}px, ${activeCrop.translateY}px) scale(${scale})`;
  };

  let isDragging = false;
  let dragStart = { x: 0, y: 0 };
  let dragOrigin = { x: 0, y: 0 };

  cropImage.addEventListener('pointerdown', (e) => {
    if (!activeCrop) return;
    isDragging = true;
    cropImage.classList.add('is-dragging');
    cropImage.setPointerCapture(e.pointerId);
    dragStart = { x: e.clientX, y: e.clientY };
    dragOrigin = { x: activeCrop.translateX, y: activeCrop.translateY };
  });

  cropImage.addEventListener('pointermove', (e) => {
    if (!activeCrop || !isDragging) return;
    const deltaX = e.clientX - dragStart.x;
    const deltaY = e.clientY - dragStart.y;
    activeCrop.translateX = dragOrigin.x + deltaX;
    activeCrop.translateY = dragOrigin.y + deltaY;
    updateCropTransform();
  });

  const stopDragging = (e) => {
    if (!activeCrop || !isDragging) return;
    isDragging = false;
    cropImage.classList.remove('is-dragging');
    try {
      cropImage.releasePointerCapture(e.pointerId);
    } catch (error) {
      // ignore release errors
    }
  };

  cropImage.addEventListener('pointerup', stopDragging);
  cropImage.addEventListener('pointercancel', stopDragging);

  cropZoom.addEventListener('input', (e) => {
    if (!activeCrop) return;
    activeCrop.zoom = Number(e.target.value);
    updateCropTransform();
  });

  cropReset.addEventListener('click', () => {
    if (!activeCrop) return;
    activeCrop.zoom = 1;
    cropZoom.value = '1';
    activeCrop.translateX = (cropFrame.clientWidth - activeCrop.displayWidth) / 2;
    activeCrop.translateY = (cropFrame.clientHeight - activeCrop.displayHeight) / 2;
    updateCropTransform();
  });

  cropCancel.addEventListener('click', () => {
    if (!activeCrop) return;
    activeCrop.input.value = '';
    closeCropper();
  });

  cropConfirm.addEventListener('click', () => {
    if (!activeCrop) return;
    const { input, file, aspect, previewUrl, translateX, translateY, baseScale, zoom } = activeCrop;
    const frameWidth = cropFrame.clientWidth;
    const frameHeight = cropFrame.clientHeight;
    const imageEl = new Image();
    imageEl.onload = () => {
      const scale = baseScale * zoom;
      const sx = Math.max(0, -translateX / scale);
      const sy = Math.max(0, -translateY / scale);
      const sWidth = frameWidth / scale;
      const sHeight = frameHeight / scale;

      const maxSize = 1200;
      const outputWidth = aspect >= 1 ? maxSize : Math.round(maxSize * aspect);
      const outputHeight = aspect >= 1 ? Math.round(maxSize / aspect) : maxSize;

      const canvas = document.createElement('canvas');
      canvas.width = outputWidth;
      canvas.height = outputHeight;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(imageEl, sx, sy, sWidth, sHeight, 0, 0, outputWidth, outputHeight);

      canvas.toBlob((blob) => {
        if (!blob) {
          closeCropper();
          return;
        }
        const croppedFile = new File([blob], file.name, { type: blob.type, lastModified: file.lastModified });
        applyFileToInput(input, croppedFile);
        const croppedUrl = URL.createObjectURL(blob);
        setPreviewImage(input, croppedUrl);
        setProfilePreviewImage(input, croppedUrl);
        closeCropper();
      }, file.type || 'image/jpeg', 0.92);
    };
    imageEl.src = previewUrl;
  });

  // Image preview for file uploads with cropping
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
      const aspect = parseAspect(input.dataset.cropAspect);
      if (file && file.type.startsWith('image/') && aspect) {
        openCropper(file, input, aspect);
        return;
      }
      if (file && file.type.startsWith('image/')) {
        const reader = new FileReader();
        reader.onload = (event) => {
          setPreviewImage(input, event.target.result);
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
