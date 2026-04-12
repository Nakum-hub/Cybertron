# Cybertron — Autonomous Web3 Cyber Defense Platform

## Design Guidelines

### Design References (Primary Inspiration)
- **Palantir.com**: Dark, data-driven command center aesthetic
- **Iron Man's JARVIS UI**: Holographic, futuristic HUD elements
- **Cyberpunk 2077 UI**: Neon accents, glitch effects, dark atmosphere
- **Style**: Cyberpunk Minimalism + Glassmorphism + 3D Command Center

### Color Palette
- Primary Background: #0A0A0F (Deep Space Black)
- Secondary Background: #12121A (Dark Navy)
- Card Background: rgba(15, 23, 42, 0.6) (Glassmorphic Dark)
- Accent Cyan: #00F0FF (Neon Cyan - primary accent)
- Accent Magenta: #FF006E (Neon Magenta - secondary accent)
- Accent Purple: #8B5CF6 (Electric Purple - tertiary)
- Success Green: #00FF88 (Matrix Green)
- Warning: #FFB800 (Amber)
- Danger: #FF3366 (Hot Red)
- Text Primary: #FFFFFF
- Text Secondary: #94A3B8 (Slate Gray)
- Border Glow: rgba(0, 240, 255, 0.2) (Cyan Glow)

### Typography
- Font Family: "Inter" (clean, modern, tech-forward)
- Heading1: Inter 800 (56px) - Hero titles
- Heading2: Inter 700 (40px) - Section titles
- Heading3: Inter 600 (24px) - Card titles
- Body: Inter 400 (16px) - Paragraphs
- Caption: Inter 500 (14px) - Labels, badges
- Monospace: "JetBrains Mono" for code/data displays

### Key Component Styles
- **Glassmorphic Cards**: bg-slate-900/60 backdrop-blur-xl border border-cyan-500/20 rounded-2xl
- **Buttons Primary**: bg-gradient-to-r from-cyan-500 to-blue-600, white text, hover glow
- **Buttons Secondary**: border border-cyan-500/40, transparent bg, cyan text
- **Glow Effects**: box-shadow with cyan/magenta neon glow on hover
- **Badges**: Small rounded pills with gradient backgrounds

### Layout & Spacing
- Hero: Full viewport height with 3D globe background
- Sections: py-24 to py-32 for breathing room
- Cards: 24px gaps in grids, 32px internal padding
- Max content width: 1280px centered

### Animation Guidelines
- Scroll-triggered fade-in-up animations (staggered)
- Floating/pulsing glow effects on idle elements
- Smooth parallax on scroll
- Micro-interactions on hover (scale, glow, color shift)
- Data ticker animations for threat feeds

### Images to Generate
1. **hero-cyber-globe.jpg** — A dark futuristic holographic globe with glowing network connections, cyber grid lines, neon cyan and magenta data streams flowing around it, deep space background (Style: photorealistic, dark cyberpunk)
2. **threat-dashboard-preview.jpg** — A futuristic cybersecurity dashboard with dark UI, showing threat maps, risk meters, data visualizations, holographic charts, neon accents (Style: photorealistic, UI screenshot feel)
3. **blockchain-security-abstract.jpg** — Abstract visualization of blockchain nodes connected by glowing chains, digital locks, encrypted data streams, dark background with cyan and purple glow (Style: photorealistic, abstract tech)
4. **zero-trust-shield.jpg** — A futuristic digital shield with layers of protection, biometric scan lines, fingerprint hologram, surrounded by floating security icons, dark cyberpunk aesthetic (Style: photorealistic, dark futuristic)

---

## Development Tasks

### Files to Create (8 files max)
1. **src/pages/Index.tsx** — Main landing page orchestrating all sections
2. **src/components/HeroSection.tsx** — 3D animated hero with particle effects, globe, CTA
3. **src/components/FeaturesSection.tsx** — Four feature cards with hover animations
4. **src/components/ThreatDashboard.tsx** — Live threat dashboard preview with animated elements
5. **src/components/ArchitectureSection.tsx** — Tech stack & security architecture visual breakdown
6. **src/components/PricingSection.tsx** — Three-tier pricing (Free, ₹1,499/mo, Enterprise)
7. **src/components/AuthShowcase.tsx** — Authentication & Web3 login showcase + Footer/CTA
8. **src/lib/animations.ts** — Shared animation utilities, intersection observer hooks

### Implementation Notes
- Use CSS animations + Tailwind for all effects (no Three.js to keep bundle small & reliable)
- Simulate 3D feel with CSS transforms, gradients, and layered animations
- Use SVG for globe/network visualizations (lightweight, performant)
- Intersection Observer for scroll-triggered animations
- All sections dark-mode cyberpunk aesthetic
- Responsive: mobile-first approach