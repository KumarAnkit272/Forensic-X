"""
CYBER FORENSIC TOOLKIT - Single File Edition
Python 3.10+
Educational, read-only analysis of files and user-provided exports.

Optional packages:
    python -m pip install Pillow reportlab pytsk3

Run:
    python cyber_forensic_toolkit.py

Safety:
- Use only evidence you own or are authorized to examine.
- The application reads source files; it does not modify them.
- For serious investigations, analyze a verified forensic copy and validate
  findings with established forensic tools and procedures.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from pathlib import Path
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
import sqlite3
import hashlib
import mimetypes
import os
import csv
import json
import textwrap

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "cyber_forensic_cases.db"
CHUNK_SIZE = 1024 * 1024
BG = "#101820"
PANEL = "#17232e"
GREEN = "#00e6a0"
WHITE = "#f2f5f7"
MUTED = "#a9bac7"


# ------------------------- Core forensic functions -------------------------

def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def file_metadata(path):
    p = Path(path)
    stat = p.stat()
    return {
        "File name": p.name,
        "Full path": str(p.resolve()),
        "Size (bytes)": stat.st_size,
        "Extension": p.suffix.lower() or "(none)",
        "MIME guess": mimetypes.guess_type(p.name)[0] or "Unknown",
        "Modified time": datetime.fromtimestamp(stat.st_mtime).astimezone().isoformat(timespec="seconds"),
        "Created/changed time": datetime.fromtimestamp(stat.st_ctime).astimezone().isoformat(timespec="seconds"),
        "SHA-256": sha256_file(path),
    }


def file_signature(path):
    signatures = [
        (bytes.fromhex("89504e470d0a1a0a"), "PNG image"),
        (bytes.fromhex("ffd8ff"), "JPEG image"),
        (b"GIF87a", "GIF image"),
        (b"GIF89a", "GIF image"),
        (b"%PDF-", "PDF document"),
        (bytes.fromhex("504b0304"), "ZIP-based file"),
        (b"MZ", "Windows executable"),
        (bytes.fromhex("7f454c46"), "ELF executable"),
        (b"SQLite format 3\x00", "SQLite database"),
    ]
    with open(path, "rb") as stream:
        header = stream.read(32)
    for signature, label in signatures:
        if header.startswith(signature):
            return label
    return "Unknown / not in built-in signature list"


def keyword_search(path, keyword, max_bytes=5_000_000):
    size = os.path.getsize(path)
    if size > max_bytes:
        raise ValueError(f"File exceeds the {max_bytes:,}-byte text-search limit.")
    data = Path(path).read_bytes()
    if b"\x00" in data[:8192]:
        raise ValueError("Binary-looking file detected; text search skipped.")
    content = data.decode("utf-8", errors="replace")
    return [
        (number, line[:500])
        for number, line in enumerate(content.splitlines(), 1)
        if keyword.casefold() in line.casefold()
    ]


def analyze_email(path):
    with open(path, "rb") as stream:
        msg = BytesParser(policy=policy.default).parse(stream)
    return {
        "From": str(msg.get("From", "")),
        "To": str(msg.get("To", "")),
        "CC": str(msg.get("Cc", "")),
        "Subject": str(msg.get("Subject", "")),
        "Date": str(msg.get("Date", "")),
        "Message-ID": str(msg.get("Message-ID", "")),
        "Received header count": len(msg.get_all("Received", [])),
        "Caution": "Header fields alone do not authenticate the sender or prove message origin."
    }


def analyze_image(path):
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
    except ImportError:
        raise RuntimeError("Pillow missing. Install it with: python -m pip install Pillow")
    with Image.open(path) as img:
        result = {
            "Format": img.format,
            "Mode": img.mode,
            "Dimensions": f"{img.width} x {img.height}",
        }
        exif = img.getexif()
        for key, value in exif.items():
            result[TAGS.get(key, str(key))] = str(value)[:500]
        if not exif:
            result["EXIF"] = "No EXIF metadata found"
        return result


def analyze_browser_export(path):
    """Summarize a user-provided CSV/JSON browser-history or download export."""
    suffix = Path(path).suffix.lower()
    if suffix == ".csv":
        with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as stream:
            rows = list(csv.DictReader(stream))
        return {
            "Format": "CSV",
            "Rows": len(rows),
            "Columns": list(rows[0].keys()) if rows else [],
            "First 10 rows": rows[:10],
        }
    if suffix == ".json":
        with open(path, "r", encoding="utf-8", errors="replace") as stream:
            data = json.load(stream)
        count = len(data) if isinstance(data, (list, dict)) else 1
        return {
            "Format": "JSON",
            "Top-level type": type(data).__name__,
            "Items/keys": count,
            "Preview": str(data)[:3000],
        }
    raise ValueError("Select a CSV or JSON export file.")


def analyze_log(path):
    terms = ("error", "failed", "warning", "denied", "login", "logout", "critical")
    counts = {term: 0 for term in terms}
    matches = []
    with open(path, "r", encoding="utf-8", errors="replace") as stream:
        for line_no, line in enumerate(stream, 1):
            found = [term for term in terms if term in line.casefold()]
            for term in found:
                counts[term] += 1
            if found:
                matches.append((line_no, ", ".join(found), line.strip()[:500]))
    return counts, matches[:500]


def inspect_disk_image(path):
    """Optional read-only partition-table listing via pytsk3 / The Sleuth Kit."""
    try:
        import pytsk3
    except ImportError:
        raise RuntimeError("pytsk3 is optional and is not installed. Try: python -m pip install pytsk3")
    image = pytsk3.Img_Info(path)
    try:
        volume = pytsk3.Volume_Info(image)
        result = []
        for part in volume:
            result.append({
                "Partition address": getattr(part, "addr", ""),
                "Start sector": getattr(part, "start", ""),
                "Length (sectors)": getattr(part, "len", ""),
                "Description": str(getattr(part, "desc", "")).strip(),
            })
        return result
    except Exception as exc:
        raise RuntimeError(
            "Partition table could not be parsed. The selected image may be a "
            "filesystem image, unsupported format, or damaged. " + str(exc)
        )


# ------------------------------- Database ----------------------------------

class CaseDatabase:
    def __init__(self):
        self.initialize()

    def connect(self):
        con = sqlite3.connect(DB_PATH)
        con.row_factory = sqlite3.Row
        return con

    def initialize(self):
        with self.connect() as con:
            con.executescript("""
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS cases(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                investigator TEXT,
                notes TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS evidence(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                path TEXT NOT NULL,
                filename TEXT NOT NULL,
                size INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                added_at TEXT NOT NULL,
                UNIQUE(case_id, path),
                FOREIGN KEY(case_id) REFERENCES cases(id)
            );
            CREATE TABLE IF NOT EXISTS audit(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                evidence_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES cases(id),
                FOREIGN KEY(evidence_id) REFERENCES evidence(id)
            );
            """)

    def create_case(self, name, investigator, notes):
        with self.connect() as con:
            cur = con.execute(
                "INSERT INTO cases(name,investigator,notes,created_at) VALUES(?,?,?,?)",
                (name, investigator, notes, utc_now())
            )
            return cur.lastrowid

    def cases(self):
        with self.connect() as con:
            return con.execute("SELECT * FROM cases ORDER BY id DESC").fetchall()

    def add_evidence(self, case_id, path, size, digest):
        resolved = str(Path(path).resolve())
        with self.connect() as con:
            cur = con.execute(
                """INSERT OR IGNORE INTO evidence
                (case_id,path,filename,size,sha256,added_at) VALUES(?,?,?,?,?,?)""",
                (case_id, resolved, Path(path).name, size, digest, utc_now())
            )
            row = con.execute(
                "SELECT id FROM evidence WHERE case_id=? AND path=?",
                (case_id, resolved)
            ).fetchone()
            return row["id"], cur.rowcount == 1

    def evidence(self, case_id):
        with self.connect() as con:
            return con.execute(
                "SELECT * FROM evidence WHERE case_id=? ORDER BY id DESC",
                (case_id,)
            ).fetchall()

    def one_evidence(self, evidence_id):
        with self.connect() as con:
            return con.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()

    def audit(self, case_id, action, details="", evidence_id=None):
        with self.connect() as con:
            con.execute(
                """INSERT INTO audit(case_id,evidence_id,action,details,timestamp)
                VALUES(?,?,?,?,?)""",
                (case_id, evidence_id, action, details, utc_now())
            )

    def audit_rows(self, case_id):
        with self.connect() as con:
            return con.execute(
                "SELECT * FROM audit WHERE case_id=? ORDER BY id DESC",
                (case_id,)
            ).fetchall()


# ------------------------------- PDF/TXT report ----------------------------
def generate_report(case, evidence, audit, output_path):

    from collections import Counter
    from pathlib import Path
    from datetime import datetime

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.units import mm

    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        PageBreak,
        KeepTogether
    )

    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart

    from xml.sax.saxutils import escape

    out = Path(output_path)

    if out.suffix.lower() != ".pdf":
        out = out.with_suffix(".pdf")

    # -------------------- DOCUMENT --------------------

    doc = SimpleDocTemplate(
        str(out),
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontSize=21,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#12304A"),
        spaceAfter=15
    ))

    styles.add(ParagraphStyle(
        name="SectionHeading",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#087F5B"),
        spaceBefore=12,
        spaceAfter=8
    ))

    styles.add(ParagraphStyle(
        name="SmallText",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
        wordWrap="CJK"
    ))

    story = []

    # -------------------- HELPER --------------------

    def add_section(title):
        story.append(Paragraph(escape(title), styles["SectionHeading"]))

    def make_table(data, widths=None):
        table = Table(
            data,
            colWidths=widths,
            repeatRows=1,
            hAlign="LEFT"
        )

        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0),
             colors.HexColor("#12304A")),

            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),

            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),

            ("FONTSIZE", (0, 0), (-1, -1), 8),

            ("GRID", (0, 0), (-1, -1), 0.4,
             colors.HexColor("#B7C4CE")),

            ("VALIGN", (0, 0), (-1, -1), "TOP"),

            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),

            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),

            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#EDF3F7")])
        ]))

        return table

    def safe_text(value):
        return escape(str(value if value is not None else ""))

    # -------------------- COVER --------------------

    story.append(Spacer(1, 35 * mm))

    story.append(Paragraph(
        "CYBER FORENSIC TOOLKIT",
        styles["ReportTitle"]
    ))

    story.append(Paragraph(
        "DIGITAL FORENSIC INVESTIGATION REPORT",
        styles["Heading2"]
    ))

    story.append(Spacer(1, 10 * mm))

    story.append(Paragraph(
        f"<b>Case ID:</b> {safe_text(case['id'])}",
        styles["Normal"]
    ))

    story.append(Paragraph(
        f"<b>Case Name:</b> {safe_text(case['name'])}",
        styles["Normal"]
    ))

    story.append(Paragraph(
        f"<b>Investigator:</b> "
        f"{safe_text(case['investigator'] or 'Not specified')}",
        styles["Normal"]
    ))

    story.append(Paragraph(
        f"<b>Generated On:</b> "
        f"{datetime.now().astimezone().strftime('%d-%m-%Y %H:%M:%S')}",
        styles["Normal"]
    ))

    story.append(Spacer(1, 20 * mm))

    story.append(Paragraph(
        "This report contains the registered evidence details, "
        "integrity information and recorded investigation activities.",
        styles["BodyText"]
    ))

    story.append(PageBreak())

    # -------------------- SUMMARY --------------------

    add_section("1. INVESTIGATION SUMMARY")

    total_evidence = len(evidence)

    total_size = sum(int(item["size"] or 0) for item in evidence)

    total_audit = len(audit)

    summary_data = [
        ["Metric", "Value"],
        ["Total Evidence Files", str(total_evidence)],
        ["Total Evidence Size", f"{total_size / (1024 * 1024):.2f} MB"],
        ["Total Audit Activities", str(total_audit)]
    ]

    story.append(make_table(
        summary_data,
        [75 * mm, 75 * mm]
    ))

    story.append(Spacer(1, 10))

    # -------------------- EVIDENCE REGISTER --------------------

    add_section("2. EVIDENCE REGISTER")

    if evidence:

        evidence_data = [[
            "ID", "Filename", "Size (Bytes)", "SHA-256"
        ]]

        for item in evidence:

            evidence_data.append([
                str(item["id"]),
                Paragraph(safe_text(item["filename"]), styles["SmallText"]),
                str(item["size"]),
                Paragraph(safe_text(item["sha256"]), styles["SmallText"])
            ])

        story.append(make_table(
            evidence_data,
            [12 * mm, 45 * mm, 25 * mm, 75 * mm]
        ))

    else:

        story.append(Paragraph(
            "No evidence files registered for this case.",
            styles["BodyText"]
        ))

    story.append(Spacer(1, 10))

    # -------------------- AUTOMATIC GRAPHS --------------------

    add_section("3. DATA VISUALIZATION")

    # Graph 1: Evidence file types

    file_types = Counter()

    for item in evidence:

        extension = Path(item["filename"]).suffix.lower()

        file_types[extension if extension else "No Extension"] += 1

    if len(file_types) >= 2:

        story.append(Paragraph(
            "<b>3.1 Evidence Distribution by File Type</b>",
            styles["Normal"]
        ))

        drawing = Drawing(400, 220)

        pie = Pie()

        pie.x = 115
        pie.y = 20
        pie.width = 180
        pie.height = 180

        labels = list(file_types.keys())
        values = list(file_types.values())

        pie.data = values
        pie.labels = labels

        pie.slices.strokeWidth = 0.5

        drawing.add(pie)

        story.append(drawing)
        story.append(Spacer(1, 12))

    # Graph 2: Evidence size

    size_items = [
        item for item in evidence
        if int(item["size"] or 0) > 0
    ]

    if len(size_items) >= 2:

        story.append(Paragraph(
            "<b>3.2 Evidence File Size Comparison</b>",
            styles["Normal"]
        ))

        drawing = Drawing(450, 220)

        chart = VerticalBarChart()

        chart.x = 45
        chart.y = 35
        chart.height = 150
        chart.width = 360

        chart.data = [[
            round(int(item["size"]) / (1024 * 1024), 2)
            for item in size_items
        ]]

        chart.categoryAxis.categoryNames = [
            str(item["filename"])[:14]
            for item in size_items
        ]

        chart.categoryAxis.labels.angle = 25
        chart.categoryAxis.labels.fontSize = 7

        chart.valueAxis.valueMin = 0
        chart.valueAxis.labelTextFormat = "%.1f"

        chart.bars[0].fillColor = colors.HexColor("#087F5B")

        drawing.add(chart)

        story.append(drawing)
        story.append(Spacer(1, 12))

    # Graph 3: Audit activity distribution

    audit_types = Counter(
        item["action"] for item in audit
    )

    if len(audit_types) >= 2:

        story.append(Paragraph(
            "<b>3.3 Investigation Activity Distribution</b>",
            styles["Normal"]
        ))

        drawing = Drawing(450, 230)

        chart = VerticalBarChart()

        chart.x = 45
        chart.y = 40
        chart.height = 150
        chart.width = 360

        chart.data = [
            list(audit_types.values())
        ]

        chart.categoryAxis.categoryNames = [
            str(action)[:15]
            for action in audit_types.keys()
        ]

        chart.categoryAxis.labels.angle = 25
        chart.categoryAxis.labels.fontSize = 7

        chart.valueAxis.valueMin = 0
        chart.valueAxis.labelTextFormat = "%d"

        chart.bars[0].fillColor = colors.HexColor("#2463A6")

        drawing.add(chart)

        story.append(drawing)
        story.append(Spacer(1, 12))

    if not evidence and not audit:
        story.append(Paragraph(
            "Graphs were skipped because sufficient data was unavailable.",
            styles["BodyText"]
        ))

    # -------------------- CHAIN OF CUSTODY --------------------

    story.append(PageBreak())

    add_section("4. CHAIN OF CUSTODY / AUDIT HISTORY")

    if audit:

        audit_data = [[
            "Timestamp", "Evidence ID", "Action", "Details"
        ]]

        for item in audit:

            audit_data.append([
                Paragraph(safe_text(item["timestamp"]), styles["SmallText"]),
                str(item["evidence_id"] or "-"),
                Paragraph(safe_text(item["action"]), styles["SmallText"]),
                Paragraph(safe_text(item["details"] or ""), styles["SmallText"])
            ])

        story.append(make_table(
            audit_data,
            [37 * mm, 20 * mm, 35 * mm, 65 * mm]
        ))

    else:

        story.append(Paragraph(
            "No audit activities recorded.",
            styles["BodyText"]
        ))

    # -------------------- EVIDENCE PATH DETAILS --------------------

    add_section("5. EVIDENCE SOURCE DETAILS")

    for item in evidence:

        story.append(KeepTogether([
            Paragraph(
                f"<b>Evidence ID:</b> {safe_text(item['id'])}",
                styles["BodyText"]
            ),

            Paragraph(
                f"<b>File:</b> {safe_text(item['filename'])}",
                styles["SmallText"]
            ),

            Paragraph(
                f"<b>Original Path:</b> {safe_text(item['path'])}",
                styles["SmallText"]
            ),

            Paragraph(
                f"<b>SHA-256:</b> {safe_text(item['sha256'])}",
                styles["SmallText"]
            ),

            Paragraph(
                f"<b>Registered:</b> {safe_text(item['added_at'])}",
                styles["SmallText"]
            ),

            Spacer(1, 8)
        ]))

    # -------------------- DISCLAIMER --------------------

    add_section("6. DISCLAIMER")

    disclaimer = (
        "This is an educational, tool-generated forensic report. "
        "It is not a certified forensic examination. "
        "File metadata and timestamps may be incomplete or altered. "
        "A SHA-256 hash match indicates matching content at the time "
        "of verification; it does not independently establish authenticity "
        "or ownership. Findings should be independently validated."
    )

    story.append(Paragraph(
        disclaimer,
        styles["BodyText"]
    ))

    # -------------------- FOOTER --------------------

    def add_page_number(canvas, document):

        canvas.saveState()

        canvas.setFont("Helvetica", 8)

        canvas.setFillColor(colors.grey)

        canvas.drawString(
            15 * mm,
            10 * mm,
            "Cyber Forensic Toolkit | Educational Report"
        )

        canvas.drawRightString(
            195 * mm,
            10 * mm,
            f"Page {document.page}"
        )

        canvas.restoreState()

    doc.build(
        story,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number
    )

    return str(out)




# --------------------------------- GUI --------------------------------------

class CyberForensicToolkit:
    def __init__(self, root):
        self.root = root
        self.root.title("Cyber Forensic Toolkit | Digital Evidence Lab")
        self.root.geometry("1180x780")
        self.root.minsize(950, 650)
        self.root.configure(bg=BG)
        self.db = CaseDatabase()
        self.case_id = None
        self.case_record = None
        self.case_rows = []
        self.setup_style()
        self.build_header()
        self.build_case_bar()
        self.build_tabs()
        self.refresh_cases()

    def setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL, foreground=WHITE, padding=(13, 9))
        style.map("TNotebook.Tab", background=[("selected", "#006b50")],
                  foreground=[("selected", "white")])
        style.configure("Treeview", background=PANEL, foreground=WHITE,
                        fieldbackground=PANEL, rowheight=27)
        style.configure("Treeview.Heading", background="#006b50", foreground="white")
        style.map("Treeview", background=[("selected", "#245c50")])

    def button(self, parent, label, command, color="#006b50"):
        return tk.Button(parent, text=label, command=command, bg=color, fg="white",
                         activebackground="#008f68", activeforeground="white",
                         relief="flat", padx=10, pady=7, cursor="hand2")

    def build_header(self):
        tk.Label(self.root, text="CYBER FORENSIC TOOLKIT",
                 bg=BG, fg=GREEN, font=("Arial", 23, "bold")).pack(pady=(13, 2))
        tk.Label(self.root, text="DIGITAL EVIDENCE • INTEGRITY • INVESTIGATION • REPORTING",
                 bg=BG, fg=MUTED, font=("Arial", 9, "bold")).pack(pady=(0, 10))

    def build_case_bar(self):
        bar = tk.Frame(self.root, bg=PANEL, padx=10, pady=9)
        bar.pack(fill="x", padx=13, pady=5)
        tk.Label(bar, text="ACTIVE CASE", bg=PANEL, fg=GREEN,
                 font=("Arial", 9, "bold")).pack(side="left")
        self.case_combo = ttk.Combobox(bar, state="readonly", width=42)
        self.case_combo.pack(side="left", padx=9)
        self.case_combo.bind("<<ComboboxSelected>>", self.select_case)
        self.button(bar, "＋ New Case", self.new_case, "#007a59").pack(side="left", padx=3)
        self.button(bar, "Refresh", self.refresh_cases, "#334b5d").pack(side="left", padx=3)
        self.case_status = tk.Label(bar, text="No case selected", bg=PANEL, fg=WHITE)
        self.case_status.pack(side="right")

    def build_tabs(self):
        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(fill="both", expand=True, padx=13, pady=10)
        self.tab_evidence = tk.Frame(self.tabs, bg=BG)
        self.tab_file = tk.Frame(self.tabs, bg=BG)
        self.tab_special = tk.Frame(self.tabs, bg=BG)
        self.tab_audit = tk.Frame(self.tabs, bg=BG)
        self.tabs.add(self.tab_evidence, text="Evidence Management")
        self.tabs.add(self.tab_file, text="File & Disk Analysis")
        self.tabs.add(self.tab_special, text="Specialized Forensics")
        self.tabs.add(self.tab_audit, text="Chain of Custody & Reports")
        self.build_evidence_tab()
        self.build_file_tab()
        self.build_special_tab()
        self.build_audit_tab()

    def make_output(self, parent):
        box = tk.Text(parent, bg=PANEL, fg=GREEN, insertbackground=WHITE,
                      font=("Consolas", 10), wrap="word", padx=10, pady=10)
        box.pack(fill="both", expand=True, padx=10, pady=8)
        return box

    def set_output(self, box, text):
        box.delete("1.0", tk.END)
        box.insert(tk.END, text)
        box.see("1.0")

    def require_case(self):
        if not self.case_id:
            messagebox.showwarning("Case required", "Please create or select a case first.")
            return False
        return True

    def build_evidence_tab(self):
        toolbar = tk.Frame(self.tab_evidence, bg=BG)
        toolbar.pack(fill="x", padx=10, pady=8)
        self.button(toolbar, "＋ Register Evidence File(s)", self.register_evidence,
                    "#007a59").pack(side="left", padx=4)
        self.button(toolbar, "Refresh List", self.refresh_evidence,
                    "#334b5d").pack(side="left", padx=4)
        self.button(toolbar, "Evidence Details", self.evidence_details,
                    "#334b5d").pack(side="left", padx=4)
        columns = ("id", "filename", "size", "sha256", "added")
        self.evidence_tree = ttk.Treeview(self.tab_evidence, columns=columns, show="headings")
        widths = (55, 210, 105, 390, 175)
        for col, width in zip(columns, widths):
            self.evidence_tree.heading(col, text=col.upper())
            self.evidence_tree.column(col, width=width, anchor="w")
        self.evidence_tree.pack(fill="both", expand=True, padx=10, pady=8)
        tk.Label(self.tab_evidence,
                 text="Evidence registration stores the file path and SHA-256; source files are not copied or edited.",
                 bg=BG, fg=MUTED, wraplength=1000).pack(pady=(0, 8))

    def build_file_tab(self):
        toolbar = tk.Frame(self.tab_file, bg=BG)
        toolbar.pack(fill="x", padx=8, pady=8)
        actions = [
            ("Metadata + Signature", self.metadata_selected),
            ("Verify SHA-256", self.verify_selected),
            ("Find Duplicates", self.find_duplicates),
            ("Keyword Search", self.keyword_selected),
            ("Disk Image Partitions", self.disk_image_analysis),
        ]
        for label, action in actions:
            self.button(toolbar, label, action).pack(side="left", padx=3)
        self.file_output = self.make_output(self.tab_file)

    def build_special_tab(self):
        toolbar = tk.Frame(self.tab_special, bg=BG)
        toolbar.pack(fill="x", padx=8, pady=8)
        actions = [
            ("Email .eml", self.email_analysis),
            ("Image EXIF", self.image_analysis),
            ("Browser CSV/JSON", self.browser_analysis),
            ("Log Analyzer", self.log_analysis),
        ]
        for label, action in actions:
            self.button(toolbar, label, action).pack(side="left", padx=4)
        self.special_output = self.make_output(self.tab_special)

    def build_audit_tab(self):
        toolbar = tk.Frame(self.tab_audit, bg=BG)
        toolbar.pack(fill="x", padx=8, pady=8)
        self.button(toolbar, "Refresh Audit", self.refresh_audit, "#334b5d").pack(side="left", padx=4)
        self.button(toolbar, "Add Case Note", self.add_case_note).pack(side="left", padx=4)
        self.button(toolbar, "Generate PDF/TXT Report", self.make_report, "#007a59").pack(side="left", padx=4)
        self.audit_output = self.make_output(self.tab_audit)

    # Case handling
    def refresh_cases(self):
        self.case_rows = self.db.cases()
        self.case_combo["values"] = [f"{row['id']} - {row['name']}" for row in self.case_rows]
        if self.case_rows:
            if self.case_id and any(r["id"] == self.case_id for r in self.case_rows):
                index = next(i for i, r in enumerate(self.case_rows) if r["id"] == self.case_id)
            else:
                index = 0
            self.case_combo.current(index)
            self.select_case()
        else:
            self.case_id = None
            self.case_record = None
            self.case_status.config(text="No case selected")
            self.refresh_evidence()
            self.refresh_audit()

    def new_case(self):
        name = simpledialog.askstring("Create Case", "Enter case name:", parent=self.root)
        if not name or not name.strip():
            return
        investigator = simpledialog.askstring("Investigator", "Investigator name (optional):",
                                               parent=self.root) or ""
        notes = simpledialog.askstring("Case Notes", "Short case description (optional):",
                                       parent=self.root) or ""
        self.case_id = self.db.create_case(name.strip(), investigator.strip(), notes.strip())
        self.db.audit(self.case_id, "CASE_CREATED", f"Case created: {name.strip()}")
        self.refresh_cases()

    def select_case(self, event=None):
        index = self.case_combo.current()
        if index < 0 or index >= len(self.case_rows):
            return
        self.case_record = self.case_rows[index]
        self.case_id = self.case_record["id"]
        self.case_status.config(text=f"Case #{self.case_id}: {self.case_record['name']}")
        self.refresh_evidence()
        self.refresh_audit()

    # Evidence handling
    def register_evidence(self):
        if not self.require_case():
            return
        paths = filedialog.askopenfilenames(parent=self.root, title="Select evidence file(s)")
        if not paths:
            return
        for path in paths:
            try:
                metadata = file_metadata(path)
                evidence_id, inserted = self.db.add_evidence(
                    self.case_id, path, metadata["Size (bytes)"], metadata["SHA-256"])
                action = "EVIDENCE_REGISTERED" if inserted else "EVIDENCE_ALREADY_REGISTERED"
                self.db.audit(self.case_id, action,
                              f"{Path(path).name}; SHA-256={metadata['SHA-256']}", evidence_id)
            except Exception as exc:
                messagebox.showerror("Evidence registration error", f"{path}\n\n{exc}")
        self.refresh_evidence()
        self.refresh_audit()

    def refresh_evidence(self):
        if not hasattr(self, "evidence_tree"):
            return
        for item in self.evidence_tree.get_children():
            self.evidence_tree.delete(item)
        if not self.case_id:
            return
        for row in self.db.evidence(self.case_id):
            self.evidence_tree.insert("", "end", iid=str(row["id"]), values=(
                row["id"], row["filename"], row["size"], row["sha256"], row["added_at"]
            ))

    def selected_evidence(self):
        if not self.require_case():
            return None
        selected = self.evidence_tree.selection()
        if not selected:
            messagebox.showinfo("Select evidence", "Select an evidence row first.")
            return None
        return self.db.one_evidence(int(selected[0]))

    def evidence_details(self):
        row = self.selected_evidence()
        if row:
            self.set_output(self.file_output, json.dumps(dict(row), indent=4, ensure_ascii=False))
            self.tabs.select(self.tab_file)

    # File analysis
    def metadata_selected(self):
        row = self.selected_evidence()
        if not row:
            return
        try:
            result = file_metadata(row["path"])
            result["Detected signature"] = file_signature(row["path"])
            self.set_output(self.file_output, json.dumps(result, indent=4, ensure_ascii=False))
            self.db.audit(self.case_id, "METADATA_AND_SIGNATURE_ANALYSIS", row["filename"], row["id"])
            self.refresh_audit()
            self.tabs.select(self.tab_file)
        except Exception as exc:
            messagebox.showerror("Metadata analysis", str(exc))

    def verify_selected(self):
        row = self.selected_evidence()
        if not row:
            return
        try:
            current = sha256_file(row["path"])
            match = current.lower() == row["sha256"].lower()
            status = "MATCH - current file content matches registered hash." if match else \
                     "MISMATCH - current file content differs from registered hash."
            output = (
                f"Evidence: {row['filename']}\n"
                f"Registered SHA-256: {row['sha256']}\n"
                f"Current SHA-256:    {current}\n\n"
                f"RESULT: {status}\n\n"
                "A match confirms the bytes match the registration-time hash; it does not "
                "prove who created the file or when it was originally created."
            )
            self.set_output(self.file_output, output)
            self.db.audit(self.case_id, "HASH_VERIFICATION",
                          f"{row['filename']}: {'MATCH' if match else 'MISMATCH'}", row["id"])
            self.refresh_audit()
            self.tabs.select(self.tab_file)
        except Exception as exc:
            messagebox.showerror("Hash verification", str(exc))

    def find_duplicates(self):
        if not self.require_case():
            return
        rows = self.db.evidence(self.case_id)
        groups = {}
        for row in rows:
            groups.setdefault(row["sha256"], []).append(row["filename"])
        duplicates = {digest: names for digest, names in groups.items() if len(names) > 1}
        self.set_output(self.file_output,
                        json.dumps(duplicates, indent=4) if duplicates else
                        "No duplicate SHA-256 hashes found among registered evidence.")
        self.db.audit(self.case_id, "DUPLICATE_HASH_CHECK",
                      f"{len(duplicates)} duplicate hash group(s) found.")
        self.refresh_audit()
        self.tabs.select(self.tab_file)

    def keyword_selected(self):
        row = self.selected_evidence()
        if not row:
            return
        keyword = simpledialog.askstring("Keyword Search", "Enter keyword to search:",
                                         parent=self.root)
        if not keyword:
            return
        try:
            hits = keyword_search(row["path"], keyword)
            output = f"File: {row['filename']}\nKeyword: {keyword}\nMatches: {len(hits)}\n\n"
            output += "\n".join(f"Line {number}: {line}" for number, line in hits) or "No matches found."
            self.set_output(self.file_output, output)
            self.db.audit(self.case_id, "KEYWORD_SEARCH",
                          f"{row['filename']}; keyword={keyword}; hits={len(hits)}", row["id"])
            self.refresh_audit()
            self.tabs.select(self.tab_file)
        except Exception as exc:
            messagebox.showerror("Keyword search", str(exc))

    def disk_image_analysis(self):
        path = filedialog.askopenfilename(parent=self.root, title="Select disk image",
            filetypes=[("Disk images", "*.dd *.img *.raw *.001"), ("All files", "*.*")])
        if not path:
            return
        try:
            result = inspect_disk_image(path)
            self.set_output(self.file_output, json.dumps(result, indent=4, ensure_ascii=False))
            if self.case_id:
                self.db.audit(self.case_id, "DISK_IMAGE_PARTITION_ANALYSIS", Path(path).name)
                self.refresh_audit()
            self.tabs.select(self.tab_file)
        except Exception as exc:
            messagebox.showerror("Disk image analysis", str(exc))

    # Specialized analysis
    def choose_file(self, title, filetypes):
        return filedialog.askopenfilename(parent=self.root, title=title, filetypes=filetypes)

    def log_special_action(self, action, path):
        if self.case_id:
            self.db.audit(self.case_id, action, Path(path).name)
            self.refresh_audit()

    def email_analysis(self):
        path = self.choose_file("Select EML email", [("Email files", "*.eml"), ("All files", "*.*")])
        if not path:
            return
        try:
            result = analyze_email(path)
            self.set_output(self.special_output, json.dumps(result, indent=4, ensure_ascii=False))
            self.log_special_action("EMAIL_HEADER_ANALYSIS", path)
        except Exception as exc:
            messagebox.showerror("Email analysis", str(exc))

    def image_analysis(self):
        path = self.choose_file("Select image", [("Image files", "*.jpg *.jpeg *.png *.tif *.tiff"), ("All files", "*.*")])
        if not path:
            return
        try:
            result = analyze_image(path)
            self.set_output(self.special_output, json.dumps(result, indent=4, ensure_ascii=False))
            self.log_special_action("IMAGE_EXIF_ANALYSIS", path)
        except Exception as exc:
            messagebox.showerror("Image analysis", str(exc))

    def browser_analysis(self):
        path = self.choose_file("Select browser export", [("CSV/JSON", "*.csv *.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            result = analyze_browser_export(path)
            self.set_output(self.special_output, json.dumps(result, indent=4, ensure_ascii=False, default=str))
            self.log_special_action("BROWSER_EXPORT_ANALYSIS", path)
        except Exception as exc:
            messagebox.showerror("Browser export analysis", str(exc))

    def log_analysis(self):
        path = self.choose_file("Select log file", [("Log/text files", "*.log *.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            counts, matches = analyze_log(path)
            output = "KEYWORD COUNTS\n" + json.dumps(counts, indent=4) + "\n\nMATCHED LINES\n"
            output += "\n".join(
                f"Line {number} [{terms}]: {line}" for number, terms, line in matches
            ) or "No matching lines."
            self.set_output(self.special_output, output)
            self.log_special_action("LOG_FILE_ANALYSIS", path)
        except Exception as exc:
            messagebox.showerror("Log analysis", str(exc))

    # Audit and reporting
    def add_case_note(self):
        if not self.require_case():
            return
        note = simpledialog.askstring("Add Case Note", "Enter investigation note:",
                                      parent=self.root)
        if note and note.strip():
            self.db.audit(self.case_id, "CASE_NOTE", note.strip())
            self.refresh_audit()

    def refresh_audit(self):
        if not hasattr(self, "audit_output"):
            return
        if not self.case_id:
            self.set_output(self.audit_output, "Create or select a case to view its audit trail.")
            return
        rows = self.db.audit_rows(self.case_id)
        output = "\n".join(
            f"{r['timestamp']} | Evidence {r['evidence_id']} | {r['action']} | {r['details'] or ''}"
            for r in rows
        )
        self.set_output(self.audit_output, output or "No audit events recorded.")

    def make_report(self):
        if not self.require_case():
            return
        case = next((row for row in self.db.cases() if row["id"] == self.case_id), None)
        if case is None:
            messagebox.showerror("Report", "Selected case could not be found.")
            return
        path = filedialog.asksaveasfilename(
            parent=self.root, title="Save forensic report",
            defaultextension=".pdf",
            filetypes=[("PDF report", "*.pdf"), ("Text report", "*.txt")]
        )
        if not path:
            return
        try:
            output = generate_report(case, self.db.evidence(self.case_id),
                                     self.db.audit_rows(self.case_id), path)
            self.db.audit(self.case_id, "REPORT_GENERATED", output)
            self.refresh_audit()
            messagebox.showinfo("Report created", f"Report saved:\n{output}")
        except Exception as exc:
            messagebox.showerror("Report generation", str(exc))


def main():
    root = tk.Tk()
    CyberForensicToolkit(root)
    root.mainloop()


if __name__ == "__main__":
    main()
