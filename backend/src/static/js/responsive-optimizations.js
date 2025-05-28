// Responsive Optimizations JavaScript

// Smooth Navigation System - DISABLED (using base.html version)
/*
// SmoothNavigation class disabled to prevent conflicts with base.html version
// The enhanced SmoothNavigation in base.html handles all navigation functionality
if (!window.SmoothNavigation) {
  window.SmoothNavigation = class {
  constructor() {
    this.init();
  }

  init() {
    this.setupEventListeners();
    this.preloadLinks();
  }

  setupEventListeners() {
    // Content transition on navigation
    document.addEventListener('click', (e) => {
      const link = e.target.closest('a[href]');
      if (link && !e.ctrlKey && !e.metaKey && !e.shiftKey && !e.altKey) {
        const url = link.getAttribute('href');
        if (url && url.startsWith('/') && !url.startsWith('//')) {
          e.preventDefault();
          this.navigateTo(url);
        }
      }
    });
  }

  preloadLinks() {
    // Preload links in viewport
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const link = entry.target;
          const url = link.getAttribute('href');
          if (url && url.startsWith('/')) {
            const preloadLink = document.createElement('link');
            preloadLink.rel = 'prefetch';
            preloadLink.href = url;
            document.head.appendChild(preloadLink);
          }
          observer.unobserve(link);
        }
      });
    });

    document.querySelectorAll('a[href^="/"]').forEach(link => {
      observer.observe(link);
    });
  }

  async navigateTo(url) {
    const main = document.querySelector('main');
    if (!main) return;

    // Add transition class
    main.style.opacity = '0';
    main.style.transform = 'translateY(10px)';

    try {
      const response = await fetch(url);
      const html = await response.text();
      const parser = new DOMParser();
      const doc = parser.parseFromString(html, 'text/html');
      const newContent = doc.querySelector('main');
      const newTitle = doc.querySelector('title');

      if (newContent) {
        // Update content with smooth transition
        setTimeout(() => {
          main.innerHTML = newContent.innerHTML;
          if (newTitle) document.title = newTitle.textContent;
          
          // Restore visibility
          main.style.opacity = '1';
          main.style.transform = 'translateY(0)';

          // Update URL
          window.history.pushState({}, '', url);

          // Initialize any scripts
          this.initScripts(newContent);
        }, 150);
      }
    } catch (error) {
      console.error('Navigation failed:', error);
      window.location.href = url; // Fallback
    }
  }

  initScripts(content) {
    // Re-run scripts in new content
    content.querySelectorAll('script').forEach(script => {
      const newScript = document.createElement('script');
      Array.from(script.attributes).forEach(attr => {
        newScript.setAttribute(attr.name, attr.value);
      });
      newScript.textContent = script.textContent;
      script.parentNode.replaceChild(newScript, script);
    });
    }
  };
}
*/

// Page Visibility Performance Optimizations
class VisibilityOptimizer {
  constructor() {
    this.hidden = false;
    this.visibilityChange = null;
    this.init();
  }

  init() {
    // Set visibility properties
    if (typeof document.hidden !== "undefined") {
      this.hidden = "hidden";
      this.visibilityChange = "visibilitychange";
    } else if (typeof document.msHidden !== "undefined") {
      this.hidden = "msHidden";
      this.visibilityChange = "msvisibilitychange";
    } else if (typeof document.webkitHidden !== "undefined") {
      this.hidden = "webkitHidden";
      this.visibilityChange = "webkitvisibilitychange";
    }

    if (this.visibilityChange) {
      document.addEventListener(this.visibilityChange, () => this.handleVisibilityChange());
    }
  }

  handleVisibilityChange() {
    if (document[this.hidden]) {
      // Page is hidden
      this.pauseNonEssentialOperations();
    } else {
      // Page is visible
      this.resumeOperations();
    }
  }

  pauseNonEssentialOperations() {
    // Pause non-essential animations and operations
    document.body.classList.add('reduce-motion');
    
    // Pause video elements
    document.querySelectorAll('video').forEach(video => {
      if (!video.hasAttribute('data-keep-playing')) {
        video.pause();
      }
    });

    // Reduce animation frame rate
    document.body.style.setProperty('--animation-duration', '0.001s');
  }

  resumeOperations() {
    // Resume normal operations
    document.body.classList.remove('reduce-motion');
    
    // Resume videos that were playing
    document.querySelectorAll('video').forEach(video => {
      if (video.hasAttribute('data-was-playing')) {
        video.play();
        video.removeAttribute('data-was-playing');
      }
    });

    // Restore animation duration
    document.body.style.removeProperty('--animation-duration');
  }
}

// Initialize optimizations
document.addEventListener('DOMContentLoaded', () => {
  // SmoothNavigation is handled by base.html - no initialization needed here
  console.log('Responsive optimizations loaded - SmoothNavigation handled by base.html');

  // Initialize visibility optimizer
  new VisibilityOptimizer();

  // Setup transition animations
  document.body.style.setProperty('--transition-duration', '0.3s');
  document.body.classList.add('transitions-enabled');

  // Add CSS for transitions
  const style = document.createElement('style');
  style.textContent = `
    .transitions-enabled * {
      transition: opacity var(--transition-duration) ease-in-out,
                  transform var(--transition-duration) ease-in-out;
    }

    .reduce-motion * {
      animation: none !important;
      transition: none !important;
    }

    @media (prefers-reduced-motion: reduce) {
      .transitions-enabled * {
        transition: none !important;
      }
    }
  `;
  document.head.appendChild(style);
});