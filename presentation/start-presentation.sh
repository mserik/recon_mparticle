#!/bin/bash

# Start Presentation Server
# This script starts a local HTTP server to view the HTML presentations

echo "=========================================="
echo "Advanced Web Application Exploitation"
echo "Training Presentation Server"
echo "=========================================="
echo ""

# Check if Python 3 is available
if command -v python3 &> /dev/null; then
    echo "✓ Python 3 found"
    echo ""
    echo "Starting HTTP server on port 8000..."
    echo ""
    echo "Open your browser to:"
    echo "  → http://localhost:8000/index.html"
    echo ""
    echo "Keyboard shortcuts:"
    echo "  → / Space : Next slide"
    echo "  ← : Previous slide"
    echo "  Esc : Overview mode"
    echo "  S : Speaker notes"
    echo "  F : Fullscreen"
    echo ""
    echo "Press Ctrl+C to stop the server"
    echo "=========================================="
    echo ""

    # Start server
    python3 -m http.server 8000

elif command -v python &> /dev/null; then
    echo "✓ Python found"
    echo ""
    echo "Starting HTTP server on port 8000..."
    echo ""
    echo "Open your browser to:"
    echo "  → http://localhost:8000/index.html"
    echo ""
    echo "Press Ctrl+C to stop the server"
    echo "=========================================="
    echo ""

    # Start server (Python 2)
    python -m SimpleHTTPServer 8000

elif command -v php &> /dev/null; then
    echo "✓ PHP found"
    echo ""
    echo "Starting HTTP server on port 8000..."
    echo ""
    echo "Open your browser to:"
    echo "  → http://localhost:8000/index.html"
    echo ""
    echo "Press Ctrl+C to stop the server"
    echo "=========================================="
    echo ""

    # Start server
    php -S localhost:8000

else
    echo "❌ Error: No suitable HTTP server found"
    echo ""
    echo "Please install one of the following:"
    echo "  • Python 3: apt install python3"
    echo "  • PHP: apt install php"
    echo ""
    echo "Or open index.html directly in your browser"
    exit 1
fi
