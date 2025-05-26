/**
 * StudentVC Responsive Optimizations
 * Performance and UX improvements for all device sizes
 */

(function() {
    'use strict';

    // Debounce function for performance
    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    // Viewport optimization
    class ViewportOptimizer {
        constructor() {
            this.init();
        }

        init() {
            this.handleViewportChanges();
            this.optimizeForDevice();
            this.setupResponsiveLogo();
        }

        handleViewportChanges() {
            const handleResize = debounce(() => {
                this.adjustLayoutForViewport();
                this.optimizeMenuVisibility();
            }, 150);

            window.addEventListener('resize', handleResize);
            window.addEventListener('orientationchange', handleResize);
        }

        adjustLayoutForViewport() {
            const viewport = window.innerWidth;
            const nav = document.querySelector('nav');
            const logo = document.querySelector('nav img');
            
            if (viewport < 768) {
                // Mobile optimizations
                if (nav) nav.classList.add('mobile-optimized');
                if (logo) {
                    logo.style.height = '4rem'; // Still large on mobile
                    logo.style.maxWidth = '150px';
                }
            } else if (viewport < 1024) {
                // Tablet optimizations
                if (nav) nav.classList.add('tablet-optimized');
                if (logo) {
                    logo.style.height = '5rem'; // Larger on tablet
                    logo.style.maxWidth = '200px';
                }
            } else {
                // Desktop optimizations - EXTRA LARGE
                if (nav) {
                    nav.classList.remove('mobile-optimized', 'tablet-optimized');
                }
                if (logo) {
                    logo.style.height = '6rem'; // EXTRA LARGE on desktop (96px)
                    logo.style.maxWidth = 'none';
                }
            }
        }

        optimizeMenuVisibility() {
            const menuItems = document.querySelectorAll('nav a');
            const viewport = window.innerWidth;
            
            if (viewport < 1200 && viewport >= 768) {
                // Hide text on smaller screens, show icons only
                menuItems.forEach(item => {
                    const span = item.querySelector('span');
                    const icon = item.querySelector('i');
                    if (span && icon) {
                        span.style.display = 'none';
                        icon.style.marginRight = '0';
                        item.title = span.textContent; // Add tooltip
                    }
                });
            } else {
                // Show full text and icons
                menuItems.forEach(item => {
                    const span = item.querySelector('span');
                    const icon = item.querySelector('i');
                    if (span && icon) {
                        span.style.display = 'inline';
                        icon.style.marginRight = '0.5rem';
                        item.removeAttribute('title');
                    }
                });
            }
        }

        setupResponsiveLogo() {
            const logo = document.querySelector('nav img');
            if (!logo) return;

            // Add responsive classes
            logo.classList.add('responsive-logo');
            
            // Handle logo overlap on smaller screens
            const handleLogoOverlap = () => {
                const viewport = window.innerWidth;
                const logoContainer = logo.closest('.flex');
                
                if (viewport < 640) {
                    // Prevent overlap on very small screens
                    logoContainer.style.position = 'relative';
                    logoContainer.style.zIndex = '20';
                } else {
                    // Allow overlap on larger screens
                    logoContainer.style.position = 'relative';
                    logoContainer.style.zIndex = '10';
                }
            };

            handleLogoOverlap();
            window.addEventListener('resize', debounce(handleLogoOverlap, 150));
        }

        optimizeForDevice() {
            // Touch device optimizations
            if ('ontouchstart' in window) {
                document.body.classList.add('touch-device');
                this.addTouchOptimizations();
            }

            // High DPI display optimizations
            if (window.devicePixelRatio > 1) {
                document.body.classList.add('high-dpi');
                this.optimizeForHighDPI();
            }
        }

        addTouchOptimizations() {
            // Increase touch target sizes
            const style = document.createElement('style');
            style.textContent = `
                .touch-device a, 
                .touch-device button {
                    min-height: 44px;
                    min-width: 44px;
                    padding: 12px 16px;
                }
                
                .touch-device nav a {
                    padding: 16px 20px;
                }
                
                /* Remove hover effects on touch devices */
                .touch-device *:hover {
                    background-color: inherit !important;
                    color: inherit !important;
                }
            `;
            document.head.appendChild(style);
        }

        optimizeForHighDPI() {
            // Use higher resolution images if available
            const images = document.querySelectorAll('img');
            images.forEach(img => {
                const src = img.src;
                if (src && !src.includes('@2x')) {
                    const highResSrc = src.replace(/\.(png|jpg|jpeg)$/, '@2x.$1');
                    // Test if high-res version exists
                    const testImg = new Image();
                    testImg.onload = () => {
                        img.src = highResSrc;
                    };
                    testImg.src = highResSrc;
                }
            });
        }
    }

    // Performance monitoring
    class PerformanceMonitor {
        constructor() {
            this.init();
        }

        init() {
            this.monitorPageLoad();
            this.optimizeAnimations();
            this.lazyLoadImages();
        }

        monitorPageLoad() {
            if ('performance' in window) {
                window.addEventListener('load', () => {
                    setTimeout(() => {
                        const perfData = performance.getEntriesByType('navigation')[0];
                        console.log('Page Load Performance:', {
                            loadTime: perfData.loadEventEnd - perfData.loadEventStart,
                            domContentLoaded: perfData.domContentLoadedEventEnd - perfData.domContentLoadedEventStart,
                            totalTime: perfData.loadEventEnd - perfData.fetchStart
                        });
                    }, 100);
                });
            }
        }

        optimizeAnimations() {
            // Reduce animations for slow devices
            if ('connection' in navigator && navigator.connection.effectiveType === '2g') {
                document.body.classList.add('reduce-animations');
                const style = document.createElement('style');
                style.textContent = `
                    .reduce-animations *,
                    .reduce-animations *::before,
                    .reduce-animations *::after {
                        animation-duration: 0.1s !important;
                        transition-duration: 0.1s !important;
                    }
                `;
                document.head.appendChild(style);
            }
        }

        lazyLoadImages() {
            // Enhanced lazy loading with better fallbacks
            if ('IntersectionObserver' in window) {
                const imageObserver = new IntersectionObserver((entries, observer) => {
                    entries.forEach(entry => {
                        if (entry.isIntersecting) {
                            const img = entry.target;
                            if (img.dataset.src) {
                                img.src = img.dataset.src;
                                img.removeAttribute('data-src');
                                img.classList.add('loaded');
                                observer.unobserve(img);
                            }
                        }
                    });
                }, {
                    rootMargin: '50px 0px'
                });

                document.querySelectorAll('img[data-src]').forEach(img => {
                    imageObserver.observe(img);
                });
            } else {
                // Fallback for older browsers
                document.querySelectorAll('img[data-src]').forEach(img => {
                    img.src = img.dataset.src;
                    img.removeAttribute('data-src');
                });
            }
        }
    }

    // Initialize optimizations when DOM is ready
    document.addEventListener('DOMContentLoaded', () => {
        new ViewportOptimizer();
        new PerformanceMonitor();
    });

    // Add CSS for responsive optimizations
    const responsiveCSS = document.createElement('style');
    responsiveCSS.textContent = `
        /* EXTRA LARGE Responsive logo optimizations */
        .responsive-logo {
            transition: all 0.3s ease-in-out;
            max-height: 6rem; /* EXTRA LARGE default */
            width: auto;
            height: auto;
        }
        
        /* Mobile optimizations - still prominent */
        @media (max-width: 767px) {
            .mobile-optimized {
                padding-left: 1.5rem;
                padding-right: 1.5rem;
            }
            
            .responsive-logo {
                max-height: 4rem; /* Large on mobile */
                max-width: 150px;
            }
            
            /* Improve touch targets - LARGER */
            nav a, nav button {
                padding: 20px 16px;
                font-size: 18px;
                min-height: 52px;
            }
        }
        
        /* Tablet optimizations - BIGGER */
        @media (min-width: 768px) and (max-width: 1023px) {
            .tablet-optimized .responsive-logo {
                max-height: 5rem; /* Even larger on tablet */
                max-width: 200px;
            }
            
            nav a, nav button {
                padding: 18px 14px;
                font-size: 17px;
            }
        }
        
        /* Desktop optimizations - EXTRA LARGE */
        @media (min-width: 1024px) {
            .responsive-logo {
                max-height: 6rem; /* EXTRA LARGE on desktop */
            }
            
            nav a, nav button {
                padding: 16px 24px;
                font-size: 20px;
            }
        }
        
        /* High DPI optimizations */
        .high-dpi img {
            image-rendering: -webkit-optimize-contrast;
            image-rendering: crisp-edges;
        }
        
        /* Lazy loading states */
        img[data-src] {
            opacity: 0.6;
            filter: blur(1px);
            transition: opacity 0.3s, filter 0.3s;
        }
        
        img.loaded {
            opacity: 1;
            filter: blur(0);
        }
        
        /* Accessibility improvements */
        @media (prefers-reduced-motion: reduce) {
            .responsive-logo,
            * {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
            }
        }
        
        /* Focus improvements */
        @media (prefers-contrast: high) {
            a:focus, button:focus {
                outline: 3px solid currentColor;
                outline-offset: 3px;
            }
        }
    `;
    
    document.head.appendChild(responsiveCSS);
})();