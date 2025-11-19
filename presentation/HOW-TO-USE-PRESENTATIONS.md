# How to Use the HTML Presentations

## Quick Start

### Option 1: Open Directly in Browser (Easiest)

1. Navigate to the presentation folder:
   ```bash
   cd presentation/
   ```

2. Open `index.html` in your browser:
   ```bash
   # On Linux
   firefox index.html
   # or
   google-chrome index.html

   # On macOS
   open index.html

   # On Windows
   start index.html
   ```

3. The presentation will open in your default browser!

### Option 2: Serve with HTTP Server (Recommended for Presenting)

```bash
# Using Python (recommended)
cd presentation/
python3 -m http.server 8000

# Then open browser to:
# http://localhost:8000/index.html
```

```bash
# Using Node.js
npx http-server presentation/ -p 8000
```

```bash
# Using PHP
cd presentation/
php -S localhost:8000
```

## Presentation Controls

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `→` or `Space` | Next slide |
| `←` | Previous slide |
| `↓` | Next vertical slide |
| `↑` | Previous vertical slide |
| `Home` | First slide |
| `End` | Last slide |
| `Esc` or `O` | Overview mode (see all slides) |
| `F` | Fullscreen mode |
| `S` | Speaker notes (presenter view) |
| `B` or `.` | Pause/blackout |
| `?` | Show help |

### Navigation

- **Left/Right arrows**: Move between main sections
- **Up/Down arrows**: Navigate within a section
- **Overview mode (Esc)**: See all slides at once, click to jump

### Presenter Mode

1. Press `S` to open speaker notes in a new window
2. The new window shows:
   - Current slide
   - Next slide preview
   - Speaker notes
   - Timer

## Available Presentations

### Main Presentation: `index.html`
- **Content**: Complete 6-day training overview
- **Duration**: ~45 minutes
- **Slides**: 40+ slides
- **Topics**:
  - Course overview
  - Day 1: Authentication attacks (JWT, SAML, OAuth, 2FA)
  - Day 2: Password reset & Business logic
  - Day 3: API security preview
  - Lab exercises
  - Certification info

## Customization

### Changing Theme

Edit `index.html` and modify the theme link:

```html
<!-- Current theme: black -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/reveal.js@4.5.0/dist/theme/black.css">

<!-- Available themes: -->
<!-- black, white, league, beige, sky, night, serif, simple, solarized -->

<!-- Example: Change to white theme -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/reveal.js@4.5.0/dist/theme/white.css">
```

### Changing Transition

Edit the `Reveal.initialize()` section:

```javascript
Reveal.initialize({
    transition: 'slide',  // none/fade/slide/convex/concave/zoom
    backgroundTransition: 'fade'
});
```

### Adding Your Logo

Add this after the opening `<section>` tags:

```html
<div style="position: absolute; top: 20px; right: 20px;">
    <img src="your-logo.png" style="width: 150px;">
</div>
```

## Exporting to PDF

### Method 1: Print to PDF (Best Quality)

1. Open presentation in Chrome/Chromium
2. Add `?print-pdf` to URL:
   ```
   http://localhost:8000/index.html?print-pdf
   ```
3. Press `Ctrl+P` (Print)
4. Select "Save as PDF"
5. Set margins to "None"
6. Save

### Method 2: Using decktape

```bash
# Install decktape
npm install -g decktape

# Export to PDF
decktape reveal http://localhost:8000/index.html presentation.pdf

# With custom size
decktape reveal -s 1920x1080 http://localhost:8000/index.html presentation.pdf
```

## Tips for Presenting

### Before the Presentation

1. **Test everything**:
   ```bash
   # Start server
   python3 -m http.server 8000

   # Open in browser
   firefox http://localhost:8000/index.html

   # Press 'S' for speaker view
   # Navigate through all slides
   ```

2. **Have backup**:
   - Export to PDF as backup
   - Test on presentation computer/projector
   - Check if videos/images load

3. **Prepare speaker notes**:
   - Review notes in speaker view (`S` key)
   - Add timing notes for each section

### During the Presentation

1. **Use Overview Mode**:
   - Press `Esc` to see all slides
   - Jump to specific sections quickly

2. **Use Presenter View**:
   - Press `S` for dual-screen setup
   - Show slides on projector, notes on laptop

3. **Interactive Elements**:
   - Code blocks are syntax-highlighted
   - Use arrow keys for smooth navigation
   - Use `B` to black out during discussions

## Offline Use

The presentation uses CDN links for reveal.js. For offline use:

### Download reveal.js locally:

```bash
cd presentation/

# Download reveal.js
wget https://github.com/hakimel/reveal.js/archive/refs/tags/4.5.0.zip
unzip 4.5.0.zip
mv reveal.js-4.5.0 reveal.js
```

### Update HTML links:

```html
<!-- Change from: -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/reveal.js@4.5.0/dist/reveal.css">

<!-- To: -->
<link rel="stylesheet" href="reveal.js/dist/reveal.css">
```

## Troubleshooting

### Slides not displaying correctly

**Issue**: Blank screen or CSS not loading
**Solution**:
- Check browser console for errors (F12)
- Ensure you're serving via HTTP server (not file://)
- Clear browser cache

### Code highlighting not working

**Issue**: Code appears without syntax highlighting
**Solution**:
- Check that highlight.js CDN is accessible
- Verify code language is specified: `<code class="python">`

### Speaker notes not opening

**Issue**: Pressing 'S' doesn't open speaker view
**Solution**:
- Check if pop-ups are blocked
- Try in different browser
- Serve via HTTP server

### Presentation too slow

**Issue**: Slides loading slowly
**Solution**:
- Remove large images
- Use optimized images (compress)
- Consider hosting reveal.js locally

## Advanced Features

### Adding Fragments (Incremental Reveals)

```html
<section>
    <p class="fragment">This appears first</p>
    <p class="fragment">This appears second</p>
    <p class="fragment">This appears third</p>
</section>
```

### Adding Speaker Notes

```html
<section>
    <h2>My Slide</h2>
    <p>Public content</p>

    <aside class="notes">
        These are speaker notes - only visible in presenter mode.
        Talk about XYZ here.
    </aside>
</section>
```

### Auto-Slide

```javascript
Reveal.initialize({
    autoSlide: 5000,  // Auto-advance every 5 seconds
    loop: false
});
```

### Vertical Slides

```html
<section>
    <section>
        <h2>Main Topic</h2>
    </section>
    <section>
        <h2>Subtopic 1</h2>
    </section>
    <section>
        <h2>Subtopic 2</h2>
    </section>
</section>
```

## Sharing the Presentation

### GitHub Pages (Free Hosting)

1. Push to GitHub repository
2. Go to Settings → Pages
3. Enable GitHub Pages
4. Your presentation will be at:
   ```
   https://username.github.io/repo-name/presentation/index.html
   ```

### Netlify Drop (Free, No Account Needed)

1. Go to https://app.netlify.com/drop
2. Drag the `presentation` folder
3. Get instant shareable link

### Google Drive

1. Export to PDF
2. Upload to Google Drive
3. Share link with students

## Resources

- **Reveal.js Documentation**: https://revealjs.com/
- **Reveal.js GitHub**: https://github.com/hakimel/reveal.js
- **Example Presentations**: https://revealjs.com/demo/
- **Themes**: https://revealjs.com/themes/
- **Plugins**: https://revealjs.com/plugins/

## Need Help?

Common issues and solutions:
1. **Can't open file**: Use HTTP server, not file://
2. **Slides look broken**: Check CDN accessibility
3. **Want different colors**: Change theme in HTML
4. **Need PDF**: Use print-pdf query parameter

---

**You're all set! Enjoy presenting! 🎤**
