"""
CyberSentinel Enterprise — PDF Report Generator
Produces a full Burp Suite-style professional report
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    KeepTogether, HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY, TA_RIGHT
from datetime import datetime

W, H = A4
CW   = W - 36*mm

# ── Colours ───────────────────────────────────────────────────────
NAVY     = colors.HexColor('#0D2B55')
RED      = colors.HexColor('#C62828')
DKRED    = colors.HexColor('#7F0000')
ORANGE   = colors.HexColor('#E65100')
AMBER    = colors.HexColor('#F9A825')
TEAL     = colors.HexColor('#00695C')
BLUE     = colors.HexColor('#1565C0')
PURPLE   = colors.HexColor('#6A1B9A')
GREY     = colors.HexColor('#616161')
MID      = colors.HexColor('#333333')
WHITE    = colors.white
LIGHT_R  = colors.HexColor('#FFEBEE')
LIGHT_O  = colors.HexColor('#FFF3E0')
LIGHT_Y  = colors.HexColor('#FFFDE7')
LIGHT_G  = colors.HexColor('#E8F5E9')
LIGHT_B  = colors.HexColor('#E3F2FD')
BG_CODE  = colors.HexColor('#0A0E1A')

SEV_COLORS = {
    'CRITICAL': (DKRED,    colors.HexColor('#FFCCBC')),
    'HIGH':     (ORANGE,   LIGHT_O),
    'MEDIUM':   (AMBER,    LIGHT_Y),
    'LOW':      (TEAL,     LIGHT_G),
    'INFO':     (BLUE,     LIGHT_B),
}

def ps(name, **kw):
    d = dict(fontName='Helvetica', fontSize=10, textColor=MID,
             leading=14, spaceBefore=0, spaceAfter=0)
    d.update(kw)
    return ParagraphStyle(name, **d)

def sev_bar(sev, count, max_count):
    """Return a colored severity row for the summary table."""
    bg, _ = SEV_COLORS.get(sev, (GREY, WHITE))
    pct    = int((count / max(max_count, 1)) * 100)
    return [
        Paragraph(f'<b>{sev}</b>', ps('st', textColor=WHITE, fontSize=9)),
        Paragraph(str(count), ps('sc', textColor=WHITE, fontSize=11, fontName='Helvetica-Bold')),
        Paragraph(f'{pct}% of findings', ps('sp', textColor=WHITE, fontSize=8)),
    ]

def code_block(text, max_lines=20):
    lines = text.strip().split('\n')[:max_lines]
    content = []
    for line in lines:
        clr = colors.HexColor('#80CBC4')
        if line.strip().startswith('#'):
            clr = colors.HexColor('#546E7A')
        elif '❌' in line:
            clr = colors.HexColor('#FF5252')
        elif '✅' in line:
            clr = colors.HexColor('#69F0AE')
        content.append(Paragraph(
            line.replace('<','&lt;').replace('>','&gt;') or '&nbsp;',
            ps('code', fontName='Courier', fontSize=8.5, textColor=clr,
               leading=12, spaceAfter=0, spaceBefore=0)
        ))
    tbl = Table([[content]], colWidths=[CW - 4*mm])
    tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,-1), BG_CODE),
        ('TOPPADDING',    (0,0),(-1,-1), 8),
        ('BOTTOMPADDING', (0,0),(-1,-1), 8),
        ('LEFTPADDING',   (0,0),(-1,-1), 12),
        ('RIGHTPADDING',  (0,0),(-1,-1), 12),
        ('ROUNDEDCORNERS',[4]),
    ]))
    return tbl

def finding_block(f, index):
    sev_color, sev_bg = SEV_COLORS.get(f.severity, (GREY, WHITE))
    items = []

    # Header bar
    hdr = Table([[
        Paragraph(f'<b>#{index:02d} &nbsp; {f.title}</b>',
                  ps('fh', fontName='Helvetica-Bold', fontSize=11, textColor=WHITE)),
        Paragraph(f.severity,
                  ps('fs', fontSize=9, fontName='Helvetica-Bold', textColor=WHITE,
                     alignment=TA_RIGHT)),
    ]], colWidths=[CW * 0.82, CW * 0.18])
    hdr.setStyle(TableStyle([
        ('BACKGROUND', (0,0),(-1,-1), sev_color),
        ('TOPPADDING',    (0,0),(-1,-1), 8),
        ('BOTTOMPADDING', (0,0),(-1,-1), 8),
        ('LEFTPADDING',   (0,0),(0,0), 12),
        ('LEFTPADDING',   (1,0),(1,0), 6),
        ('RIGHTPADDING',  (0,0),(-1,-1), 12),
        ('VALIGN',        (0,0),(-1,-1), 'MIDDLE'),
        ('ROUNDEDCORNERS',[4,4,0,0]),
    ]))
    items.append(hdr)

    # Meta row
    meta_data = [
        [Paragraph('<b>ID</b>', ps('ml', fontSize=8, textColor=GREY)),
         Paragraph(f.vuln_id, ps('mv', fontSize=8.5, textColor=MID)),
         Paragraph('<b>Category</b>', ps('ml', fontSize=8, textColor=GREY)),
         Paragraph(f.category, ps('mv', fontSize=8.5, textColor=MID)),
         Paragraph('<b>CVSS</b>', ps('ml', fontSize=8, textColor=GREY)),
         Paragraph(f'<b>{f.cvss_score}</b>', ps('mv', fontSize=9, textColor=sev_color, fontName='Helvetica-Bold')),
         Paragraph('<b>CVE/CWE</b>', ps('ml', fontSize=8, textColor=GREY)),
         Paragraph(f.cve or 'N/A', ps('mv', fontSize=8, textColor=MID))],
        [Paragraph('<b>Endpoint</b>', ps('ml', fontSize=8, textColor=GREY)),
         Paragraph(f.endpoint, ps('mv', fontSize=8.5, textColor=BLUE, fontName='Courier')),
         Paragraph('<b>Method</b>', ps('ml', fontSize=8, textColor=GREY)),
         Paragraph(f.method, ps('mv', fontSize=8.5, textColor=MID)),
         Paragraph('&nbsp;', ps('mv')), Paragraph('&nbsp;', ps('mv')), Paragraph('&nbsp;', ps('mv')), Paragraph('&nbsp;', ps('mv'))],
    ]
    meta_tbl = Table(meta_data, colWidths=[CW*0.09, CW*0.16, CW*0.1, CW*0.16,
                                            CW*0.07, CW*0.1, CW*0.1, CW*0.22])
    meta_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,-1), sev_bg),
        ('TOPPADDING',    (0,0),(-1,-1), 5),
        ('BOTTOMPADDING', (0,0),(-1,-1), 5),
        ('LEFTPADDING',   (0,0),(-1,-1), 8),
        ('VALIGN',        (0,0),(-1,-1), 'MIDDLE'),
        ('LINEBELOW',     (0,0),(-1,0),  0.3, sev_color),
    ]))
    items.append(meta_tbl)

    # Body
    body_rows = [
        [Paragraph('<b>Description</b>', ps('bl', fontName='Helvetica-Bold', fontSize=9, textColor=NAVY)),
         Paragraph(f.description, ps('bv', fontSize=9.5, textColor=MID, leading=14, alignment=TA_JUSTIFY))],
        [Paragraph('<b>Payload</b>', ps('bl', fontName='Helvetica-Bold', fontSize=9, textColor=NAVY)),
         Paragraph(f'<font face="Courier" size="8.5" color="#C62828">{f.payload[:300]}</font>',
                   ps('pv', fontSize=8.5, leading=13))],
        [Paragraph('<b>Evidence</b>', ps('bl', fontName='Helvetica-Bold', fontSize=9, textColor=NAVY)),
         Paragraph(f.evidence[:300], ps('ev', fontSize=9, textColor=MID, leading=13))],
    ]
    body_tbl = Table(body_rows, colWidths=[18*mm, CW - 18*mm])
    body_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,-1), colors.HexColor('#FAFBFF')),
        ('TOPPADDING',    (0,0),(-1,-1), 7),
        ('BOTTOMPADDING', (0,0),(-1,-1), 7),
        ('LEFTPADDING',   (0,0),(0,-1),  8),
        ('LEFTPADDING',   (1,0),(1,-1),  10),
        ('VALIGN',        (0,0),(-1,-1), 'TOP'),
        ('LINEBELOW',     (0,0),(-1,-2), 0.3, colors.HexColor('#E0E0E0')),
        ('BOX',           (0,0),(-1,-1), 0.5, colors.HexColor('#CFD8DC')),
    ]))
    items.append(body_tbl)

    # Fix section
    fix_hdr = Table([[
        Paragraph('🛠  FIX / REMEDIATION', ps('fixh', fontName='Helvetica-Bold', fontSize=9,
                  textColor=WHITE)),
    ]], colWidths=[CW])
    fix_hdr.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,-1), TEAL),
        ('TOPPADDING',    (0,0),(-1,-1), 5),
        ('BOTTOMPADDING', (0,0),(-1,-1), 5),
        ('LEFTPADDING',   (0,0),(-1,-1), 12),
    ]))
    items.append(fix_hdr)

    fix_body = Table([[
        Paragraph(f.fix, ps('fb', fontSize=9.5, textColor=MID, leading=14, alignment=TA_JUSTIFY)),
    ]], colWidths=[CW])
    fix_body.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,-1), LIGHT_G),
        ('TOPPADDING',    (0,0),(-1,-1), 8),
        ('BOTTOMPADDING', (0,0),(-1,-1), 8),
        ('LEFTPADDING',   (0,0),(-1,-1), 12),
        ('RIGHTPADDING',  (0,0),(-1,-1), 12),
    ]))
    items.append(fix_body)

    # Fix code
    if f.fix_code:
        items.append(code_block(f.fix_code))

    items.append(Spacer(1, 6*mm))
    return KeepTogether(items) if index <= 3 else items


def generate_report(findings: list, target: str, output_path: str):
    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm,
        topMargin=14*mm, bottomMargin=14*mm,
        title=f'CyberSentinel Report — {target}',
        author='CyberSentinel Enterprise Scanner',
    )
    story = []

    # ── COVER PAGE ────────────────────────────────────────────────
    sev_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    # Cover banner
    cover = Table([[
        Paragraph('CYBERSENTINEL', ps('c1', fontName='Helvetica-Bold', fontSize=22,
                  textColor=WHITE, alignment=TA_CENTER, spaceAfter=4)),
        Paragraph('ENTERPRISE SECURITY ASSESSMENT REPORT',
                  ps('c2', fontSize=11, textColor=colors.HexColor('#90CAF9'),
                     alignment=TA_CENTER, spaceAfter=6)),
        Paragraph(f'Target: {target}',
                  ps('c3', fontName='Helvetica-Bold', fontSize=10,
                     textColor=colors.HexColor('#80CBC4'), alignment=TA_CENTER, spaceAfter=3)),
        Paragraph(f'Generated: {datetime.now().strftime("%d %B %Y, %H:%M UTC")}',
                  ps('c4', fontSize=9, textColor=colors.HexColor('#78909C'),
                     alignment=TA_CENTER, spaceAfter=3)),
        Paragraph('Classification: CONFIDENTIAL — FOR AUTHORIZED PERSONNEL ONLY',
                  ps('c5', fontName='Helvetica-Oblique', fontSize=8.5,
                     textColor=colors.HexColor('#EF9A9A'), alignment=TA_CENTER)),
    ]], colWidths=[CW])
    cover.setStyle(TableStyle([
        ('BACKGROUND', (0,0),(-1,-1), NAVY),
        ('TOPPADDING',    (0,0),(-1,0),  18),
        ('BOTTOMPADDING', (0,-1),(-1,-1),18),
        ('LEFTPADDING',   (0,0),(-1,-1), 20),
        ('RIGHTPADDING',  (0,0),(-1,-1), 20),
        ('ROUNDEDCORNERS',[6]),
    ]))
    story.append(cover)
    story.append(Spacer(1, 8*mm))

    # Executive summary stats
    stat_data = [[
        Paragraph(f'<b>{len(findings)}</b>\n<font size="9">Total</font>',
                  ps('ss', fontSize=22, fontName='Helvetica-Bold', textColor=NAVY, alignment=TA_CENTER)),
        Paragraph(f'<b>{sev_counts["CRITICAL"]}</b>\n<font size="9">Critical</font>',
                  ps('ss2', fontSize=22, fontName='Helvetica-Bold', textColor=DKRED, alignment=TA_CENTER)),
        Paragraph(f'<b>{sev_counts["HIGH"]}</b>\n<font size="9">High</font>',
                  ps('ss3', fontSize=22, fontName='Helvetica-Bold', textColor=ORANGE, alignment=TA_CENTER)),
        Paragraph(f'<b>{sev_counts["MEDIUM"]}</b>\n<font size="9">Medium</font>',
                  ps('ss4', fontSize=22, fontName='Helvetica-Bold', textColor=AMBER, alignment=TA_CENTER)),
        Paragraph(f'<b>{sev_counts["LOW"]}</b>\n<font size="9">Low</font>',
                  ps('ss5', fontSize=22, fontName='Helvetica-Bold', textColor=TEAL, alignment=TA_CENTER)),
    ]]
    stat_tbl = Table(stat_data, colWidths=[CW/5]*5)
    stat_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(0,-1), LIGHT_B),
        ('BACKGROUND',    (1,0),(1,-1), LIGHT_R),
        ('BACKGROUND',    (2,0),(2,-1), LIGHT_O),
        ('BACKGROUND',    (3,0),(3,-1), LIGHT_Y),
        ('BACKGROUND',    (4,0),(4,-1), LIGHT_G),
        ('TOPPADDING',    (0,0),(-1,-1), 14),
        ('BOTTOMPADDING', (0,0),(-1,-1), 14),
        ('ALIGN',         (0,0),(-1,-1), 'CENTER'),
        ('VALIGN',        (0,0),(-1,-1), 'MIDDLE'),
        ('BOX',           (0,0),(-1,-1), 0.5, colors.HexColor('#CFD8DC')),
        ('INNERGRID',     (0,0),(-1,-1), 0.3, colors.HexColor('#E0E0E0')),
        ('ROUNDEDCORNERS',[6]),
    ]))
    story.append(stat_tbl)
    story.append(Spacer(1, 8*mm))

    # ── EXECUTIVE SUMMARY ────────────────────────────────────────
    exec_hdr = Table([[Paragraph('EXECUTIVE SUMMARY', ps('eh', fontName='Helvetica-Bold',
                       fontSize=10, textColor=WHITE))]],
                     colWidths=[CW])
    exec_hdr.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,-1), NAVY),
        ('TOPPADDING',    (0,0),(-1,-1), 7),
        ('BOTTOMPADDING', (0,0),(-1,-1), 7),
        ('LEFTPADDING',   (0,0),(-1,-1), 12),
        ('ROUNDEDCORNERS',[4,4,0,0]),
    ]))
    story.append(exec_hdr)

    risk_level = 'CRITICAL' if sev_counts['CRITICAL'] > 0 else ('HIGH' if sev_counts['HIGH'] > 0 else 'MEDIUM')
    exec_body = Table([[Paragraph(
        f'The security assessment of <b>{target}</b> identified <b>{len(findings)} vulnerabilities</b> '
        f'across {len(set(f.category for f in findings))} vulnerability categories. '
        f'The overall risk rating is <b>{risk_level}</b>. '
        f'<b>{sev_counts["CRITICAL"]} Critical</b> and <b>{sev_counts["HIGH"]} High</b> severity issues '
        f'require immediate remediation. Critical vulnerabilities include Remote Code Execution, '
        f'SQL Injection, Insecure Deserialization, Path Traversal, and unauthenticated sensitive data '
        f'exposure. Business logic flaws enable price manipulation, unlimited coupon abuse, and '
        f'negative wallet transfers. Immediate action is required before production deployment.',
        ps('eb', fontSize=9.5, textColor=MID, leading=15, alignment=TA_JUSTIFY)
    )]], colWidths=[CW])
    exec_body.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,-1), colors.HexColor('#F8F9FF')),
        ('TOPPADDING',    (0,0),(-1,-1), 10),
        ('BOTTOMPADDING', (0,0),(-1,-1), 10),
        ('LEFTPADDING',   (0,0),(-1,-1), 14),
        ('RIGHTPADDING',  (0,0),(-1,-1), 14),
        ('BOX',           (0,0),(-1,-1), 0.5, colors.HexColor('#CFD8DC')),
        ('ROUNDEDCORNERS',[0,0,4,4]),
    ]))
    story.append(exec_body)
    story.append(Spacer(1, 6*mm))

    # ── FINDINGS TABLE ───────────────────────────────────────────
    tbl_hdr = Table([[Paragraph('VULNERABILITY FINDINGS SUMMARY', ps('th', fontName='Helvetica-Bold',
                      fontSize=10, textColor=WHITE))]],
                    colWidths=[CW])
    tbl_hdr.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,-1), NAVY),
        ('TOPPADDING',    (0,0),(-1,-1), 7),
        ('BOTTOMPADDING', (0,0),(-1,-1), 7),
        ('LEFTPADDING',   (0,0),(-1,-1), 12),
        ('ROUNDEDCORNERS',[4,4,0,0]),
    ]))
    story.append(tbl_hdr)

    tbl_rows = [[
        Paragraph('<b>#</b>',         ps('thh', fontName='Helvetica-Bold', fontSize=8.5, textColor=WHITE)),
        Paragraph('<b>ID</b>',        ps('thh', fontName='Helvetica-Bold', fontSize=8.5, textColor=WHITE)),
        Paragraph('<b>Title</b>',     ps('thh', fontName='Helvetica-Bold', fontSize=8.5, textColor=WHITE)),
        Paragraph('<b>Category</b>',  ps('thh', fontName='Helvetica-Bold', fontSize=8.5, textColor=WHITE)),
        Paragraph('<b>Severity</b>',  ps('thh', fontName='Helvetica-Bold', fontSize=8.5, textColor=WHITE)),
        Paragraph('<b>CVSS</b>',      ps('thh', fontName='Helvetica-Bold', fontSize=8.5, textColor=WHITE)),
        Paragraph('<b>Endpoint</b>',  ps('thh', fontName='Helvetica-Bold', fontSize=8.5, textColor=WHITE)),
    ]]
    row_bgs = []
    for i, f in enumerate(findings, 1):
        sev_c, sev_bg = SEV_COLORS.get(f.severity, (GREY, WHITE))
        tbl_rows.append([
            Paragraph(str(i),        ps('td', fontSize=8.5, textColor=MID)),
            Paragraph(f.vuln_id,     ps('td', fontSize=8, textColor=MID, fontName='Courier')),
            Paragraph(f.title[:50],  ps('td', fontSize=8.5, textColor=MID)),
            Paragraph(f.category,    ps('td', fontSize=8, textColor=MID)),
            Paragraph(f'<b>{f.severity}</b>', ps('td', fontSize=8.5, textColor=sev_c, fontName='Helvetica-Bold')),
            Paragraph(str(f.cvss_score), ps('td', fontSize=8.5, textColor=sev_c, fontName='Helvetica-Bold')),
            Paragraph(f.endpoint[:35], ps('td', fontSize=7.5, textColor=GREY, fontName='Courier')),
        ])
        row_bgs.append(sev_bg if i % 2 == 0 else WHITE)

    findings_tbl = Table(tbl_rows,
                         colWidths=[CW*0.05, CW*0.1, CW*0.22, CW*0.13,
                                    CW*0.1, CW*0.07, CW*0.33])
    style = [
        ('BACKGROUND',    (0,0),(-1,0),  NAVY),
        ('TOPPADDING',    (0,0),(-1,-1), 5),
        ('BOTTOMPADDING', (0,0),(-1,-1), 5),
        ('LEFTPADDING',   (0,0),(-1,-1), 6),
        ('VALIGN',        (0,0),(-1,-1), 'MIDDLE'),
        ('BOX',           (0,0),(-1,-1), 0.5, colors.HexColor('#CFD8DC')),
        ('INNERGRID',     (0,0),(-1,-1), 0.3, colors.HexColor('#E0E0E0')),
        ('ROUNDEDCORNERS',[0,0,4,4]),
    ]
    for i, bg in enumerate(row_bgs, 1):
        style.append(('BACKGROUND', (0,i),(-1,i), bg))
    findings_tbl.setStyle(TableStyle(style))
    story.append(findings_tbl)
    story.append(PageBreak())

    # ── DETAILED FINDINGS ─────────────────────────────────────────
    detail_hdr = Table([[Paragraph('DETAILED FINDINGS', ps('dh', fontName='Helvetica-Bold',
                         fontSize=10, textColor=WHITE))]],
                       colWidths=[CW])
    detail_hdr.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,-1), NAVY),
        ('TOPPADDING',    (0,0),(-1,-1), 8),
        ('BOTTOMPADDING', (0,0),(-1,-1), 8),
        ('LEFTPADDING',   (0,0),(-1,-1), 12),
        ('ROUNDEDCORNERS',[6]),
    ]))
    story.append(detail_hdr)
    story.append(Spacer(1, 5*mm))

    for i, f in enumerate(findings, 1):
        result = finding_block(f, i)
        if isinstance(result, list):
            for item in result:
                story.append(item)
        else:
            story.append(result)

    # ── REMEDIATION PRIORITY ─────────────────────────────────────
    story.append(PageBreak())
    story.append(Table([[Paragraph('REMEDIATION ROADMAP', ps('rh', fontName='Helvetica-Bold',
                         fontSize=10, textColor=WHITE))]],
                       colWidths=[CW]))
    story[-1].setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,-1), NAVY),
        ('TOPPADDING',    (0,0),(-1,-1), 8),
        ('BOTTOMPADDING', (0,0),(-1,-1), 8),
        ('LEFTPADDING',   (0,0),(-1,-1), 12),
        ('ROUNDEDCORNERS',[6]),
    ]))
    story.append(Spacer(1, 5*mm))

    phases = [
        ('Phase 1 — Immediate (0–7 days)', DKRED,
         [f for f in findings if f.severity == 'CRITICAL']),
        ('Phase 2 — Short Term (1–4 weeks)', ORANGE,
         [f for f in findings if f.severity == 'HIGH']),
        ('Phase 3 — Medium Term (1–3 months)', AMBER,
         [f for f in findings if f.severity == 'MEDIUM']),
        ('Phase 4 — Planned (3–6 months)', TEAL,
         [f for f in findings if f.severity in ('LOW', 'INFO')]),
    ]
    for phase_name, color, phase_findings in phases:
        if not phase_findings:
            continue
        phase_hdr = Table([[
            Paragraph(f'<b>{phase_name}</b>',
                      ps('ph', fontName='Helvetica-Bold', fontSize=9.5, textColor=WHITE)),
            Paragraph(f'{len(phase_findings)} items',
                      ps('pc', fontSize=8.5, textColor=WHITE, alignment=TA_RIGHT)),
        ]], colWidths=[CW*0.85, CW*0.15])
        phase_hdr.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),(-1,-1), color),
            ('TOPPADDING',    (0,0),(-1,-1), 6),
            ('BOTTOMPADDING', (0,0),(-1,-1), 6),
            ('LEFTPADDING',   (0,0),(-1,-1), 12),
            ('VALIGN',        (0,0),(-1,-1), 'MIDDLE'),
            ('ROUNDEDCORNERS',[4,4,0,0]),
        ]))
        story.append(phase_hdr)

        phase_rows = [[
            Paragraph('<b>ID</b>',       ps('pth', fontName='Helvetica-Bold', fontSize=8, textColor=GREY)),
            Paragraph('<b>Title</b>',    ps('pth', fontName='Helvetica-Bold', fontSize=8, textColor=GREY)),
            Paragraph('<b>Endpoint</b>', ps('pth', fontName='Helvetica-Bold', fontSize=8, textColor=GREY)),
            Paragraph('<b>CVSS</b>',     ps('pth', fontName='Helvetica-Bold', fontSize=8, textColor=GREY)),
        ]]
        for pf in phase_findings:
            phase_rows.append([
                Paragraph(pf.vuln_id, ps('ptd', fontSize=8, fontName='Courier', textColor=MID)),
                Paragraph(pf.title[:60], ps('ptd2', fontSize=8.5, textColor=MID)),
                Paragraph(pf.endpoint[:45], ps('ptd3', fontSize=8, fontName='Courier', textColor=GREY)),
                Paragraph(str(pf.cvss_score), ps('ptd4', fontSize=8, textColor=color, fontName='Helvetica-Bold')),
            ])
        phase_body = Table(phase_rows, colWidths=[CW*0.13, CW*0.42, CW*0.33, CW*0.12])
        phase_body.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),(-1,0),  colors.HexColor('#F5F5F5')),
            ('TOPPADDING',    (0,0),(-1,-1), 5),
            ('BOTTOMPADDING', (0,0),(-1,-1), 5),
            ('LEFTPADDING',   (0,0),(-1,-1), 8),
            ('VALIGN',        (0,0),(-1,-1), 'MIDDLE'),
            ('BOX',           (0,0),(-1,-1), 0.5, colors.HexColor('#E0E0E0')),
            ('INNERGRID',     (0,0),(-1,-1), 0.3, colors.HexColor('#EEEEEE')),
            ('ROWBACKGROUNDS',(0,1),(-1,-1), [WHITE, colors.HexColor('#FAFAFA')] * 20),
            ('ROUNDEDCORNERS',[0,0,4,4]),
        ]))
        story.append(phase_body)
        story.append(Spacer(1, 5*mm))

    # Footer
    story.append(Spacer(1, 5*mm))
    story.append(Table([[
        Paragraph(
            f'CyberSentinel Enterprise Scanner  ·  Report generated {datetime.now().strftime("%Y-%m-%d %H:%M")}  ·  '
            f'Target: {target}  ·  CONFIDENTIAL',
            ps('foot', fontSize=7.5, textColor=GREY, alignment=TA_CENTER)
        )
    ]], colWidths=[CW]))

    doc.build(story)
    print(f'✅ Report saved: {output_path}')
    return output_path
