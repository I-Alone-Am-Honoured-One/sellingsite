// Profile menu dropdown handling
document.addEventListener('DOMContentLoaded', () => {
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

  const clamp = (value, min, max) => Math.min(Math.max(value, min), max);
  const toNumber = (value, fallback = 0) => {
    const parsed = Number(value);
    return Number.isNaN(parsed) ? fallback : parsed;
  };
  const round = (value, precision = 2) => {
    const factor = 10 ** precision;
    return Math.round(value * factor) / factor;
  };
  const getDistance = (a, b) => Math.hypot(b.x - a.x, b.y - a.y);
  const getMidpoint = (a, b) => ({ x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 });
  const isNumber = (value) => Number.isFinite(value) && !Number.isNaN(value);

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

  const ensureElement = (selector, root = document) => {
    if (!selector) return null;
    return root.querySelector(selector);
  };

  const createElement = (tag, className, text) => {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (text) el.textContent = text;
    return el;
  };

  const setPreviewImage = (input, previewUrl) => {
    const existing = input.parentElement.querySelector('.upload-preview');
    if (existing) {
      existing.remove();
    }
    preview.innerHTML = `
      <img src="${previewUrl}" alt="Preview" loading="lazy" />
    `;
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

  class ImageCropper {
    constructor() {
      this.modal = this.createModal();
      this.image = ensureElement('.image-crop-image', this.modal);
      this.frame = ensureElement('.image-crop-frame', this.modal);
      this.zoomInput = ensureElement('.image-crop-zoom', this.modal);
      this.resetButton = ensureElement('.image-crop-reset', this.modal);
      this.cancelButton = ensureElement('.image-crop-cancel', this.modal);
      this.confirmButton = ensureElement('.image-crop-confirm', this.modal);
      this.sizeLabel = ensureElement('.image-crop-size', this.modal);
      this.tipLabel = ensureElement('.image-crop-tip', this.modal);

      this.activeCrop = null;
      this.activePointers = new Map();
      this.isDragging = false;
      this.dragStart = { x: 0, y: 0 };
      this.dragOrigin = { x: 0, y: 0 };
      this.pinchState = null;
      this.objectUrl = null;
      this.resizeObserver = null;

      this.bindEvents();
    }

    createModal() {
      const modal = document.createElement('div');
      modal.className = 'image-crop-modal';
      modal.hidden = true;
      modal.innerHTML = `
        <div class="image-crop-panel" role="dialog" aria-modal="true" aria-label="Crop image">
          <div class="image-crop-header">
            <div>
              <h3>Adjust image</h3>
              <p class="image-crop-subtitle">Drag to reposition. Pinch or scroll to zoom.</p>
            </div>
            <button type="button" class="button ghost small image-crop-cancel">Cancel</button>
          </div>
          <div class="image-crop-frame" aria-live="polite">
            <img class="image-crop-image" alt="Crop preview" />
            <div class="image-crop-mask" aria-hidden="true"></div>
          </div>
          <div class="image-crop-meta">
            <span class="image-crop-size">Loading image…</span>
            <span class="image-crop-tip">Tip: use two fingers to zoom on mobile.</span>
          </div>
          <div class="image-crop-controls">
            <label>
              Zoom
              <input type="range" min="1" max="4" step="0.01" value="1" class="image-crop-zoom" />
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
    }

    bindEvents() {
      if (!this.modal) return;

      this.image.addEventListener('pointerdown', (e) => this.onPointerDown(e));
      this.image.addEventListener('pointermove', (e) => this.onPointerMove(e));
      this.image.addEventListener('pointerup', (e) => this.onPointerUp(e));
      this.image.addEventListener('pointercancel', (e) => this.onPointerUp(e));

      this.frame.addEventListener('pointerdown', (e) => this.onFramePointerDown(e));
      this.frame.addEventListener('pointermove', (e) => this.onFramePointerMove(e));
      this.frame.addEventListener('pointerup', (e) => this.onFramePointerUp(e));
      this.frame.addEventListener('pointercancel', (e) => this.onFramePointerUp(e));

      this.frame.addEventListener('wheel', (e) => this.onWheelZoom(e), { passive: false });

      this.zoomInput.addEventListener('input', (e) => {
        if (!this.activeCrop) return;
        const nextZoom = toNumber(e.target.value, 1);
        const frameRect = this.frame.getBoundingClientRect();
        const anchorX = frameRect.left + frameRect.width / 2;
        const anchorY = frameRect.top + frameRect.height / 2;
        this.applyZoom(nextZoom, anchorX, anchorY);
      });

      this.resetButton.addEventListener('click', () => this.resetCrop());
      this.cancelButton.addEventListener('click', () => this.cancelCrop());
      this.confirmButton.addEventListener('click', () => this.confirmCrop());

      window.addEventListener('resize', () => this.handleResize());
      window.addEventListener('orientationchange', () => this.handleResize());
    }

    handleResize() {
      if (!this.activeCrop) return;
      this.updateFrameDimensions();
      this.recenterIfNeeded();
    }

    observeFrame() {
      if (!('ResizeObserver' in window) || !this.frame) return;
      if (this.resizeObserver) this.resizeObserver.disconnect();
      this.resizeObserver = new ResizeObserver(() => {
        if (!this.activeCrop) return;
        this.updateFrameDimensions();
        this.recenterIfNeeded();
      });
      this.resizeObserver.observe(this.frame);
    }

    open(file, input, aspect) {
      if (!file || !input || !aspect) return;

      if (this.objectUrl) {
        URL.revokeObjectURL(this.objectUrl);
      }
      this.objectUrl = URL.createObjectURL(file);

      this.activeCrop = {
        file,
        input,
        aspect,
        previewUrl: this.objectUrl,
        zoom: 1,
        translateX: 0,
        translateY: 0,
        baseScale: 1,
        displayWidth: 0,
        displayHeight: 0,
        originalWidth: 0,
        originalHeight: 0,
        maxZoom: 4,
        minZoom: 1,
        maxOutput: 1600
      };

      this.updateFrameDimensions();
      this.modal.hidden = false;
      this.frame.classList.toggle('is-circle', input.name === 'avatar');
      this.frame.classList.toggle('is-banner', input.name === 'background');
      this.image.classList.remove('is-dragging');
      this.image.src = '';

      this.loadImage(this.objectUrl)
        .then(({ width, height }) => {
          if (!this.activeCrop) return;
          this.activeCrop.originalWidth = width;
          this.activeCrop.originalHeight = height;
          this.image.src = this.objectUrl;
          this.image.style.width = `${width}px`;
          this.image.style.height = `${height}px`;
          this.image.style.opacity = '1';

          this.calculateBaseScale();
          this.setZoomRange();
          this.centerCrop();
          this.updateSizeLabel();
          this.observeFrame();
        })
        .catch(() => {
          if (!this.activeCrop) return;
          this.sizeLabel.textContent = 'Could not load image.';
        });
    }

    loadImage(url) {
      return new Promise((resolve, reject) => {
        const image = new Image();
        image.onload = () => resolve({ width: image.naturalWidth, height: image.naturalHeight });
        image.onerror = reject;
        image.src = url;
      });
    }

    updateFrameDimensions() {
      if (!this.activeCrop) return;
      const { aspect } = this.activeCrop;
      this.frame.style.setProperty('--crop-aspect', aspect);
      const frameWidth = this.frame.clientWidth;
      if (!frameWidth) return;
      const frameHeight = frameWidth / aspect;
      this.frame.style.height = `${frameHeight}px`;
    }

    setZoomRange() {
      if (!this.activeCrop) return;
      const { originalWidth, originalHeight } = this.activeCrop;
      const frameWidth = this.frame.clientWidth;
      const frameHeight = this.frame.clientHeight;
      if (!frameWidth || !frameHeight) return;

      const minScale = Math.max(frameWidth / originalWidth, frameHeight / originalHeight);
      const extraZoom = Math.max(1, Math.min(4, Math.max(originalWidth, originalHeight) / 600));
      this.activeCrop.minZoom = 1;
      this.activeCrop.maxZoom = round(extraZoom + 1, 2);
      this.activeCrop.baseScale = minScale;
      this.zoomInput.min = this.activeCrop.minZoom.toString();
      this.zoomInput.max = this.activeCrop.maxZoom.toString();
      this.zoomInput.step = '0.01';
      this.zoomInput.value = this.activeCrop.zoom.toString();
    }

    calculateBaseScale() {
      if (!this.activeCrop) return;
      const frameWidth = this.frame.clientWidth;
      const frameHeight = this.frame.clientHeight;
      const { originalWidth, originalHeight } = this.activeCrop;
      const baseScale = Math.max(frameWidth / originalWidth, frameHeight / originalHeight);
      this.activeCrop.baseScale = baseScale;
    }

    updateSizeLabel() {
      if (!this.activeCrop || !this.sizeLabel) return;
      const { originalWidth, originalHeight, aspect } = this.activeCrop;
      const output = this.getOutputSize(aspect);
      this.sizeLabel.textContent = `Source: ${originalWidth}×${originalHeight}px · Output: ${output.width}×${output.height}px`;
    }

    getOutputSize(aspect) {
      if (!this.activeCrop) return { width: 0, height: 0 };
      const maxOutput = this.activeCrop.maxOutput;
      const width = aspect >= 1 ? maxOutput : Math.round(maxOutput * aspect);
      const height = aspect >= 1 ? Math.round(maxOutput / aspect) : maxOutput;
      return { width, height };
    }

    applyZoom(nextZoom, anchorX, anchorY) {
      if (!this.activeCrop) return;
      const { minZoom, maxZoom } = this.activeCrop;
      const clampedZoom = clamp(nextZoom, minZoom, maxZoom);
      const frameRect = this.frame.getBoundingClientRect();
      const localX = anchorX - frameRect.left;
      const localY = anchorY - frameRect.top;

      const prevScale = this.activeCrop.baseScale * this.activeCrop.zoom;
      const nextScale = this.activeCrop.baseScale * clampedZoom;
      const imageX = (localX - this.activeCrop.translateX) / prevScale;
      const imageY = (localY - this.activeCrop.translateY) / prevScale;

      this.activeCrop.zoom = clampedZoom;
      this.activeCrop.translateX = localX - imageX * nextScale;
      this.activeCrop.translateY = localY - imageY * nextScale;
      this.zoomInput.value = clampedZoom.toFixed(2);

      this.updateCropTransform();
    }

    updateCropTransform() {
      if (!this.activeCrop) return;
      const { baseScale, zoom, originalWidth, originalHeight } = this.activeCrop;
      const scale = baseScale * zoom;
      const frameWidth = this.frame.clientWidth;
      const frameHeight = this.frame.clientHeight;
      const displayWidth = originalWidth * scale;
      const displayHeight = originalHeight * scale;

      this.activeCrop.displayWidth = displayWidth;
      this.activeCrop.displayHeight = displayHeight;

      const minX = frameWidth - displayWidth;
      const minY = frameHeight - displayHeight;
      this.activeCrop.translateX = clamp(this.activeCrop.translateX, minX, 0);
      this.activeCrop.translateY = clamp(this.activeCrop.translateY, minY, 0);

      this.image.style.transform = `translate(${this.activeCrop.translateX}px, ${this.activeCrop.translateY}px) scale(${scale})`;
    }

    centerCrop() {
      if (!this.activeCrop) return;
      const frameWidth = this.frame.clientWidth;
      const frameHeight = this.frame.clientHeight;
      const scale = this.activeCrop.baseScale * this.activeCrop.zoom;
      const displayWidth = this.activeCrop.originalWidth * scale;
      const displayHeight = this.activeCrop.originalHeight * scale;
      this.activeCrop.translateX = (frameWidth - displayWidth) / 2;
      this.activeCrop.translateY = (frameHeight - displayHeight) / 2;
      this.updateCropTransform();
    }

    recenterIfNeeded() {
      if (!this.activeCrop) return;
      const frameWidth = this.frame.clientWidth;
      const frameHeight = this.frame.clientHeight;
      const scale = this.activeCrop.baseScale * this.activeCrop.zoom;
      const displayWidth = this.activeCrop.originalWidth * scale;
      const displayHeight = this.activeCrop.originalHeight * scale;
      if (displayWidth < frameWidth || displayHeight < frameHeight) {
        this.centerCrop();
      } else {
        this.updateCropTransform();
      }
    }

    resetCrop() {
      if (!this.activeCrop) return;
      this.activeCrop.zoom = 1;
      this.zoomInput.value = '1';
      this.calculateBaseScale();
      this.centerCrop();
    }

    cancelCrop() {
      if (!this.activeCrop) return;
      this.activeCrop.input.value = '';
      this.close();
    }

    close() {
      this.modal.hidden = true;
      this.image.src = '';
      this.image.style.transform = '';
      this.image.style.opacity = '';
      this.image.classList.remove('is-dragging');
      this.activePointers.clear();
      this.pinchState = null;
      this.activeCrop = null;

      if (this.objectUrl) {
        URL.revokeObjectURL(this.objectUrl);
        this.objectUrl = null;
      }

      if (this.resizeObserver) {
        this.resizeObserver.disconnect();
        this.resizeObserver = null;
      }
    }

    confirmCrop() {
      if (!this.activeCrop) return;
      const { input, file, aspect, translateX, translateY, baseScale, zoom } = this.activeCrop;
      const frameWidth = this.frame.clientWidth;
      const frameHeight = this.frame.clientHeight;
      const imageEl = new Image();
      imageEl.onload = () => {
        const scale = baseScale * zoom;
        const sx = Math.max(0, -translateX / scale);
        const sy = Math.max(0, -translateY / scale);
        const sWidth = frameWidth / scale;
        const sHeight = frameHeight / scale;

        const output = this.getOutputSize(aspect);

        const canvas = document.createElement('canvas');
        canvas.width = output.width;
        canvas.height = output.height;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(imageEl, sx, sy, sWidth, sHeight, 0, 0, output.width, output.height);

        canvas.toBlob((blob) => {
          if (!blob) {
            this.close();
            return;
          }
          const croppedFile = new File([blob], file.name, { type: blob.type, lastModified: file.lastModified });
          applyFileToInput(input, croppedFile);
          const croppedUrl = URL.createObjectURL(blob);
          setPreviewImage(input, croppedUrl);
          setProfilePreviewImage(input, croppedUrl);
          this.close();
        }, file.type || 'image/jpeg', 0.92);
      };
      imageEl.src = this.activeCrop.previewUrl;
    }

    onPointerDown(e) {
      if (!this.activeCrop) return;
      this.isDragging = true;
      this.image.classList.add('is-dragging');
      this.image.setPointerCapture(e.pointerId);
      this.dragStart = { x: e.clientX, y: e.clientY };
      this.dragOrigin = { x: this.activeCrop.translateX, y: this.activeCrop.translateY };
    }

    onPointerMove(e) {
      if (!this.activeCrop || !this.isDragging) return;
      if (this.activePointers.size > 1) return;
      const deltaX = e.clientX - this.dragStart.x;
      const deltaY = e.clientY - this.dragStart.y;
      this.activeCrop.translateX = this.dragOrigin.x + deltaX;
      this.activeCrop.translateY = this.dragOrigin.y + deltaY;
      this.updateCropTransform();
    }

    onPointerUp(e) {
      if (!this.activeCrop || !this.isDragging) return;
      this.isDragging = false;
      this.image.classList.remove('is-dragging');
      try {
        this.image.releasePointerCapture(e.pointerId);
      } catch (error) {
        // ignore release errors
      }
    }

    onFramePointerDown(e) {
      if (!this.activeCrop || e.pointerType !== 'touch') return;
      this.activePointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
      this.frame.setPointerCapture(e.pointerId);
      if (this.activePointers.size === 2) {
        const [first, second] = Array.from(this.activePointers.values());
        const distance = getDistance(first, second);
        this.pinchState = { distance, zoom: this.activeCrop.zoom };
        this.isDragging = false;
        this.image.classList.remove('is-dragging');
      }
    }

    onFramePointerMove(e) {
      if (!this.activeCrop || e.pointerType !== 'touch') return;
      if (!this.activePointers.has(e.pointerId)) return;
      this.activePointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (this.activePointers.size !== 2 || !this.pinchState) return;

      const [first, second] = Array.from(this.activePointers.values());
      const distance = getDistance(first, second);
      const midpoint = getMidpoint(first, second);
      const zoomFactor = distance / this.pinchState.distance;
      this.applyZoom(this.pinchState.zoom * zoomFactor, midpoint.x, midpoint.y);
    }

    onFramePointerUp(e) {
      if (e.pointerType !== 'touch') return;
      this.activePointers.delete(e.pointerId);
      if (this.activePointers.size < 2) {
        this.pinchState = null;
      }
    }

    onWheelZoom(e) {
      if (!this.activeCrop) return;
      e.preventDefault();
      const delta = -e.deltaY;
      const zoomStep = delta > 0 ? 0.08 : -0.08;
      const frameRect = this.frame.getBoundingClientRect();
      const anchorX = frameRect.left + e.offsetX;
      const anchorY = frameRect.top + e.offsetY;
      this.applyZoom(this.activeCrop.zoom + zoomStep, anchorX, anchorY);
    }
  }

  const cropper = new ImageCropper();

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
        cropper.open(file, input, aspect);
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
