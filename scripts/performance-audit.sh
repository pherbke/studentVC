#!/bin/bash
# Performance Audit Script for StudentVC

set -e

echo "🔍 StudentVC Performance Audit"
echo "============================="

cd "$(dirname "$0")/.."

# Start local server for testing
echo "🚀 Starting local server for performance testing..."
cd backend

# Check if server is already running
if curl -f http://localhost:8080/health &> /dev/null; then
    echo "✅ Server already running on port 8080"
    SERVER_RUNNING=true
else
    echo "🔄 Starting development server..."
    docker compose up -d
    echo "⏳ Waiting for server to start..."
    sleep 10
    SERVER_RUNNING=false
fi

# Performance testing function
test_page_performance() {
    local url=$1
    local page_name=$2
    
    echo ""
    echo "📊 Testing $page_name performance..."
    echo "URL: $url"
    
    # Test with curl for basic metrics
    echo "⏱️  Response time test:"
    curl -w "  - Total time: %{time_total}s\n  - DNS lookup: %{time_namelookup}s\n  - TCP connect: %{time_connect}s\n  - Time to first byte: %{time_starttransfer}s\n  - Download time: %{time_pretransfer}s\n  - Size: %{size_download} bytes\n" \
         -o /dev/null -s "$url"
    
    # Test with lighthouse-cli if available
    if command -v lighthouse &> /dev/null; then
        echo "🏆 Lighthouse audit:"
        lighthouse "$url" \
            --only-categories=performance,accessibility,best-practices \
            --output=json \
            --output-path="/tmp/lighthouse-$page_name.json" \
            --chrome-flags="--headless --no-sandbox" \
            --quiet
        
        # Extract key metrics
        local perf_score=$(cat "/tmp/lighthouse-$page_name.json" | grep -o '"performance":[0-9.]*' | cut -d: -f2)
        local accessibility_score=$(cat "/tmp/lighthouse-$page_name.json" | grep -o '"accessibility":[0-9.]*' | cut -d: -f2)
        local best_practices_score=$(cat "/tmp/lighthouse-$page_name.json" | grep -o '"best-practices":[0-9.]*' | cut -d: -f2)
        
        echo "  - Performance Score: $perf_score"
        echo "  - Accessibility Score: $accessibility_score"
        echo "  - Best Practices Score: $best_practices_score"
    else
        echo "💡 Install lighthouse for detailed performance metrics: npm install -g lighthouse"
    fi
}

# Test different pages
test_page_performance "http://localhost:8080" "Home"
test_page_performance "http://localhost:8080/issuer" "Issuer"
test_page_performance "http://localhost:8080/verifier/" "Verifier"

# Bundle size analysis
echo ""
echo "📦 Bundle Size Analysis"
echo "======================"

# Check static asset sizes
if [ -d "src/static" ]; then
    echo "📁 Static file sizes:"
    find src/static -name "*.js" -o -name "*.css" | while read file; do
        size=$(du -h "$file" | cut -f1)
        echo "  - $file: $size"
    done
fi

# Check template sizes
echo ""
echo "📄 Template sizes:"
find src/templates -name "*.html" | while read file; do
    size=$(du -h "$file" | cut -f1)
    lines=$(wc -l < "$file")
    echo "  - $file: $size ($lines lines)"
done

# Memory usage test
echo ""
echo "💾 Memory Usage Test"
echo "==================="

# Get container memory usage if using Docker
if command -v docker &> /dev/null; then
    container_id=$(docker ps | grep backend | awk '{print $1}' | head -1)
    if [ ! -z "$container_id" ]; then
        echo "🐳 Docker container memory usage:"
        docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}" $container_id
    fi
fi

# Network performance test
echo ""
echo "🌐 Network Performance"
echo "====================="

echo "📡 Testing network latency and throughput..."
# Test multiple concurrent requests
echo "  - Concurrent request test (10 requests):"
time for i in {1..10}; do
    curl -o /dev/null -s "http://localhost:8080" &
done
wait

# Test large payload handling
echo "  - Large payload test:"
curl -w "  Large page load time: %{time_total}s\n" \
     -o /dev/null -s "http://localhost:8080/verifier/settings"

# Image optimization check
echo ""
echo "🖼️  Image Optimization Check"
echo "============================"

if [ -d "src/static" ]; then
    echo "📸 Image file analysis:"
    find src/static -name "*.png" -o -name "*.jpg" -o -name "*.jpeg" -o -name "*.gif" -o -name "*.svg" | while read img; do
        size=$(du -h "$img" | cut -f1)
        if command -v identify &> /dev/null; then
            dimensions=$(identify "$img" 2>/dev/null | awk '{print $3}' || echo "unknown")
            echo "  - $img: $size ($dimensions)"
        else
            echo "  - $img: $size"
        fi
    done
    
    echo ""
    echo "💡 Image optimization recommendations:"
    echo "  - Use WebP format for better compression"
    echo "  - Implement responsive images with srcset"
    echo "  - Use appropriate image sizes for different breakpoints"
    echo "  - Consider lazy loading for non-critical images"
fi

# CSS and JS optimization check
echo ""
echo "⚡ CSS & JS Optimization"
echo "======================="

# Check for minification opportunities
echo "🗜️  Minification analysis:"
if [ -d "src/static/js" ]; then
    js_files=$(find src/static/js -name "*.js" | wc -l)
    echo "  - JavaScript files: $js_files"
    
    # Check if files are minified
    find src/static/js -name "*.js" | while read jsfile; do
        if grep -q "sourceMappingURL" "$jsfile"; then
            echo "  - $jsfile: ✅ Minified (has source map)"
        elif [[ $(head -1 "$jsfile" | wc -c) -gt 100 ]] && [[ $(head -1 "$jsfile" | grep -o " " | wc -l) -lt 5 ]]; then
            echo "  - $jsfile: ✅ Likely minified"
        else
            echo "  - $jsfile: ⚠️  Not minified"
        fi
    done
fi

if [ -d "src/static/css" ]; then
    css_files=$(find src/static/css -name "*.css" | wc -l)
    echo "  - CSS files: $css_files"
fi

# Performance recommendations
echo ""
echo "🎯 Performance Recommendations"
echo "=============================="
echo "✅ Implemented optimizations:"
echo "  - Preconnect to external domains"
echo "  - Font display: swap for web fonts"
echo "  - Lazy loading for images"
echo "  - Optimized mobile menu animations"
echo "  - Responsive logo sizing"
echo "  - Performance monitoring scripts"
echo "  - Reduced motion for accessibility"
echo "  - Touch device optimizations"
echo ""
echo "💡 Additional recommendations:"
echo "  - Consider implementing Service Worker for caching"
echo "  - Use CDN for static assets in production"
echo "  - Implement HTTP/2 server push for critical resources"
echo "  - Consider preloading next likely navigation targets"
echo "  - Monitor Core Web Vitals in production"

# Cleanup
if [ "$SERVER_RUNNING" = false ]; then
    echo ""
    echo "🛑 Stopping test server..."
    docker compose down
fi

echo ""
echo "✅ Performance audit complete!"
echo "📊 Check /tmp/lighthouse-*.json for detailed Lighthouse reports"