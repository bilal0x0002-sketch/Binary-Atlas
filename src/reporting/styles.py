"""
CSS styling module for HTML reports.
Dark mode only with 5-color rotating section themes.
"""

HTML_STYLE = """
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }

    /* ============================================
       CORE LAYOUT & TYPOGRAPHY
       ============================================ */
    body {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
        background: linear-gradient(135deg, #0a0d11 0%, #0f1419 100%);
        color: #e5e7eb;
        line-height: 1.8;
        padding: 20px;
        font-size: 15px;
        max-width: 1400px;
        margin: 0 auto;
    }

    /* ============================================
       HEADER SECTION
       ============================================ */
    .header {
        text-align: center;
        margin: 12px;
        padding: 30px 24px;
        background: linear-gradient(135deg, #0f766e 0%, #115e59 50%, #0f766e 100%);
        border-radius: 10px;
        border: 1px solid rgba(20, 184, 166, 0.15);
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.5);
        position: relative;
        overflow: hidden;
    }

    .header::before {
        content: '';
        position: absolute;
        top: -50%;
        right: -10%;
        width: 500px;
        height: 500px;
        background: radial-gradient(circle, rgba(20, 184, 166, 0.12) 0%, transparent 70%);
        border-radius: 50%;
    }

    .header h1 {
        font-size: 2.2em;
        font-weight: 800;
        color: #ffffff;
        margin-bottom: 8px;
        letter-spacing: -0.3px;
        text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
    }

    .header p {
        color: #d1fae5;
        font-size: 1.05em;
        font-weight: 400;
        letter-spacing: 0.3px;
    }

    /* ============================================
       SECTION CARDS WITH 5-COLOR ROTATION
       ============================================ */
    .section {
        background: #0f1419;
        border: 1px solid #1e2839;
        border-radius: 8px;
        padding: 20px 24px;
        margin: 20px 0;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.5);
        transition: all 0.3s cubic-bezier(0.23, 1, 0.32, 1);
        position: relative;
        overflow: hidden;
        word-wrap: break-word;
        overflow-wrap: break-word;
        max-width: 100%;
    }

    /* Color 1: TEAL (sections 1, 6, 11...) */
    .section::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 4px;
        background: linear-gradient(90deg, #14b8a6 0%, #2dd4bf 100%);
        border-radius: 8px 8px 0 0;
    }

    .section h2 {
        color: #14b8a6;
        font-size: 1.5em;
        font-weight: 700;
        margin-bottom: 18px;
        padding-bottom: 12px;
        border-bottom: 2px solid #14b8a6;
        display: flex;
        align-items: center;
        gap: 8px;
        letter-spacing: -0.3px;
        word-break: break-word;
        overflow-wrap: break-word;
    }

    /* Color 2: CYAN (sections 2, 7, 12...) */
    .section:nth-of-type(5n+2)::before {
        background: linear-gradient(90deg, #06b6d4 0%, #22d3ee 100%);
    }

    .section:nth-of-type(5n+2) h2 {
        color: #06b6d4;
        border-bottom-color: #06b6d4;
    }

    /* Color 3: GREEN (sections 3, 8, 13...) */
    .section:nth-of-type(5n+3)::before {
        background: linear-gradient(90deg, #14b8a6 0%, #2dd4bf 100%);
    }

    .section:nth-of-type(5n+3) h2 {
        color: #14b8a6;
        border-bottom-color: #14b8a6;
    }

    /* Color 4: CYAN (sections 4, 9, 14...) */
    .section:nth-of-type(5n+4)::before {
        background: linear-gradient(90deg, #06b6d4 0%, #22d3ee 100%);
    }

    .section:nth-of-type(5n+4) h2 {
        color: #06b6d4;
        border-bottom-color: #06b6d4;
    }

    /* Color 5: GREEN (sections 5, 10, 15...) */
    .section:nth-of-type(5n)::before {
        background: linear-gradient(90deg, #14b8a6 0%, #2dd4bf 100%);
    }

    .section:nth-of-type(5n) h2 {
        color: #14b8a6;
        border-bottom-color: #14b8a6;
    }

    /* ============================================
       INFO LINES & KEY-VALUE PAIRS
       ============================================ */
    .info-line {
        margin: 14px 0;
        padding: 14px 16px;
        background: rgba(6, 182, 212, 0.05);
        border-radius: 6px;
        border: 1px solid rgba(6, 182, 212, 0.15);
        border-left: 4px solid #06b6d4;
        line-height: 1.8;
        transition: all 0.2s ease;
        will-change: background, border-color;
        font-size: 0.95em;
        word-wrap: break-word;
        overflow-wrap: break-word;
        max-width: 100%;
    }

    .info-line:hover {
        border-color: rgba(6, 182, 212, 0.25);
        background: rgba(6, 182, 212, 0.1);
        transform: translateX(2px);
    }

    /* Color-matched info keys */
    .info-key {
        color: #06b6d4;
        font-weight: 700;
        font-size: 0.92em;
        letter-spacing: 0.1px;
        display: inline-block;
        min-width: 120px;
        margin-right: 8px;
    }

    .section:nth-of-type(5n+3) .info-line,
    .section:nth-of-type(5n) .info-line {
        background: rgba(20, 184, 166, 0.05);
        border-color: rgba(20, 184, 166, 0.15);
        border-left-color: #14b8a6;
    }

    .section:nth-of-type(5n+3) .info-line:hover,
    .section:nth-of-type(5n) .info-line:hover {
        border-color: rgba(20, 184, 166, 0.25);
        background: rgba(20, 184, 166, 0.1);
    }

    .info-value {
        color: #e5e7eb;
        font-weight: 500;
        word-break: break-word;
        overflow-wrap: break-word;
        display: inline;
        font-size: 0.92em;
        max-width: 100%;
    }

    .item-count {
        color: #06b6d4;
        font-weight: 700;
        background: rgba(6, 182, 212, 0.1);
        padding: 1px 4px;
        border-radius: 2px;
        font-size: 0.8em;
    }

    /* ============================================
       TABLES
       ============================================ */
    table {
        width: 100%;
        border-collapse: separate;
        border-spacing: 0;
        margin: 16px 0;
        background: #0a0d11;
        border-radius: 8px;
        overflow: hidden;
        box-shadow: 0 2px 12px rgba(0, 0, 0, 0.4);
        table-layout: auto;
    }

    th {
        background: linear-gradient(135deg, #0f766e 0%, #115e59 100%);
        color: #ffffff;
        padding: 12px 14px;
        text-align: left;
        font-weight: 700;
        text-transform: uppercase;
        font-size: 0.78em;
        letter-spacing: 0.6px;
        border-bottom: 2px solid #14b8a6;
        word-break: break-word;
        overflow-wrap: break-word;
    }

    td {
        padding: 14px 16px;
        border-bottom: 1px solid #1e2839;
        word-break: break-word;
        overflow-wrap: break-word;
        color: #d1d5db;
        font-size: 0.95em;
        max-width: 100%;
    }

    tr:hover {
        background: rgba(20, 184, 166, 0.1);
        transition: background 0.2s ease;
    }

    tr:last-child td {
        border-bottom: none;
    }

    /* ============================================
       FINDINGS & ALERTS
       ============================================ */
    .finding {
        margin: 12px 0;
        padding: 14px 16px;
        border-left: 4px solid;
        border-radius: 6px;
        background: #0a0d11;
        line-height: 1.8;
        transition: all 0.2s ease;
        font-size: 0.95em;
        will-change: transform;
        word-wrap: break-word;
        overflow-wrap: break-word;
        max-width: 100%;
    }

    .finding:hover {
        transform: translateX(4px);
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
    }

    .finding.critical {
        border-left-color: #ef4444;
        color: #fca5a5;
        background: rgba(239, 68, 68, 0.12);
    }

    .finding.high {
        border-left-color: #f97316;
        color: #fed7aa;
        background: rgba(249, 115, 22, 0.12);
    }

    .finding.medium {
        border-left-color: #eab308;
        color: #fef08a;
        background: rgba(234, 179, 8, 0.12);
    }

    .finding.low {
        border-left-color: #22c55e;
        color: #bef264;
        background: rgba(34, 197, 94, 0.12);
    }

    /* ============================================
       CODE & PRE-FORMATTED TEXT
       ============================================ */
    pre {
        background: #0a0d11;
        border: 1px solid #1e2839;
        border-left: 4px solid #06b6d4;
        border-radius: 6px;
        padding: 14px 16px;
        margin: 12px 0;
        overflow-x: auto;
        word-wrap: break-word;
        overflow-wrap: break-word;
        white-space: pre-wrap;
        font-family: 'Fira Code', 'Courier New', monospace;
        font-size: 0.9em;
        line-height: 1.6;
        color: #d1d5db;
    }

    code {
        background: rgba(6, 182, 212, 0.08);
        color: #06b6d4;
        padding: 2px 6px;
        border-radius: 3px;
        font-family: 'Fira Code', 'Courier New', monospace;
        font-size: 0.9em;
        word-break: break-word;
        overflow-wrap: break-word;
    }

    /* ============================================
       COLLAPSIBLE SECTIONS
       ============================================ */
    .spoiler-checkbox {
        display: none !important;
        visibility: hidden !important;
        width: 0 !important;
        height: 0 !important;
        margin: 0 !important;
        padding: 0 !important;
        border: none !important;
        position: absolute !important;
    }

    .spoiler-toggle {
        background: #0f766e;
        color: #d1fae5;
        border: 1px solid rgba(20, 184, 166, 0.3);
        border-radius: 6px;
        padding: 10px 12px;
        margin: 12px 0;
        font-size: 0.93em;
        font-weight: 600;
        cursor: pointer;
        display: block;
        width: 100%;
        text-align: left;
        transition: all 0.2s ease;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.35);
        will-change: transform, box-shadow;
    }

    .spoiler-toggle:hover {
        background: #115e59;
        border-color: #2dd4bf;
        box-shadow: 0 3px 8px rgba(6, 182, 212, 0.15);
        transform: translateY(-0.5px);
    }

    .spoiler-toggle::before {
        content: '▶ ';
        display: inline-block;
        transition: transform 0.3s cubic-bezier(0.23, 1, 0.32, 1);
        font-size: 0.85em;
        margin-right: 8px;
        color: #d1fae5;
    }

    .spoiler-checkbox:checked + .spoiler-toggle::before {
        transform: rotate(90deg);
    }

    .spoiler-content {
        display: none;
        margin: 0;
        padding: 12px 14px;
        background: rgba(6, 182, 212, 0.15);
        border: 1px solid rgba(6, 182, 212, 0.2);
        border-radius: 6px;
        border-left: 3px solid #06b6d4;
        margin-top: -1px;
        animation: slideDown 0.35s cubic-bezier(0.23, 1, 0.32, 1);
    }

    .spoiler-checkbox:checked + .spoiler-toggle + .spoiler-content {
        display: block;
    }

    /* ============================================
       ANALYSIS SECTIONS
       ============================================ */
    .analysis-section {
        background: #0f1419;
        border: 1px solid #1e2839;
        border-radius: 8px;
        margin: 16px 0;
        padding: 18px 20px;
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.35);
        border-left: 3px solid #14b8a6;
    }

    .analysis-section.alert-critical {
        border-left-color: #ef4444;
        background: rgba(239, 68, 68, 0.05);
    }

    .analysis-section.alert-high {
        border-left-color: #f97316;
        background: rgba(249, 115, 22, 0.05);
    }

    .section-title {
        color: #14b8a6;
        font-size: 1.2em;
        font-weight: 700;
        margin: 0 0 14px 0;
        padding-bottom: 10px;
        border-bottom: 2px solid rgba(20, 184, 166, 0.3);
        letter-spacing: -0.3px;
    }

    .analysis-section.alert-critical .section-title {
        color: #fca5a5;
    }

    .analysis-section.alert-high .section-title {
        color: #fed7aa;
    }

    /* Color-matched analysis sections with 5-color rotation */
    .analysis-section:nth-of-type(5n+2) {
        border-left-color: #06b6d4;
    }

    .analysis-section:nth-of-type(5n+2) .info-line {
        border-left-color: #06b6d4;
        background: rgba(6, 182, 212, 0.05);
        border-color: rgba(6, 182, 212, 0.1);
    }

    .analysis-section:nth-of-type(5n+2) .info-key {
        color: #06b6d4;
    }

    .analysis-section:nth-of-type(5n+3) {
        border-left-color: #14b8a6;
    }

    .analysis-section:nth-of-type(5n+3) .info-line {
        border-left-color: #14b8a6;
        background: rgba(20, 184, 166, 0.05);
        border-color: rgba(20, 184, 166, 0.1);
    }

    .analysis-section:nth-of-type(5n+3) .info-key {
        color: #14b8a6;
    }

    .analysis-section:nth-of-type(5n+4) {
        border-left-color: #06b6d4;
    }

    .analysis-section:nth-of-type(5n+4) .info-line {
        border-left-color: #06b6d4;
        background: rgba(6, 182, 212, 0.05);
        border-color: rgba(6, 182, 212, 0.1);
    }

    .analysis-section:nth-of-type(5n+4) .info-key {
        color: #06b6d4;
    }

    .analysis-section:nth-of-type(5n) {
        border-left-color: #14b8a6;
    }

    .analysis-section:nth-of-type(5n) .info-line {
        border-left-color: #14b8a6;
        background: rgba(20, 184, 166, 0.05);
        border-color: rgba(20, 184, 166, 0.1);
    }

    .analysis-section:nth-of-type(5n) .info-key {
        color: #14b8a6;
    }
        color: #d1d5db;
        line-height: 1.7;
        font-size: 0.95em;
    }

    .analysis-table {
        background: #0a0d11;
        border: 1px solid #1e2839;
        border-radius: 6px;
        padding: 12px;
        overflow-x: auto;
        font-family: 'Courier New', monospace;
        font-size: 0.9em;
        line-height: 1.6;
        color: #d1d5db;
        box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.5);
        white-space: pre-wrap;
        word-wrap: break-word;
    }

    /* ============================================
       TEXT UTILITIES
       ============================================ */
    .text-default {
        color: #cfd8dc;
        margin: 8px 0;
        font-size: 0.94em;
        word-wrap: break-word;
        overflow-wrap: break-word;
    }

    .text-subtitle {
        color: #cfd8dc;
        margin: 12px 0;
        font-weight: 600;
        margin-top: 16px;
        font-size: 1em;
        letter-spacing: -0.3px;
    }

    /* ============================================
       FOOTER
       ============================================ */
    .footer {
        text-align: center;
        margin-top: 30px;
        padding: 20px;
        color: #9ca3af;
        border-top: 1px solid #1e2839;
        font-size: 0.85em;
        font-weight: 400;
        letter-spacing: 0.2px;
        background: rgba(15, 20, 25, 0.3);
    }

    /* ============================================
       ANIMATIONS
       ============================================ */
    @keyframes fadeIn {
        from {
            opacity: 0;
            transform: translateY(5px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    @keyframes slideDown {
        from {
            opacity: 0;
            transform: translateY(-10px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    /* ============================================
       RESPONSIVE DESIGN
       ============================================ */
    @media (max-width: 768px) {
        .header {
            margin: 15px;
            padding: 25px 20px;
        }

        .header h1 {
            font-size: 1.8em;
        }

        .section {
            margin: 15px;
            padding: 20px 18px;
        }

        table {
            font-size: 0.85em;
        }

        th, td {
            padding: 10px;
        }

        .spoiler-toggle {
            padding: 10px 14px;
            font-size: 0.9em;
        }
    }

    @media (max-width: 480px) {
        .header h1 {
            font-size: 1.4em;
        }

        .section h2 {
            font-size: 1.3em;
        }

        .header {
            margin: 10px;
            padding: 20px 15px;
        }

        .section {
            margin: 10px;
            padding: 15px 12px;
        }

        .info-key {
            display: block;
            min-width: auto;
            margin-bottom: 4px;
        }
    }
"""
