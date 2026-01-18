#!/usr/bin/env python3
"""
CSV/TXT/HTML COOKIE-CUTTER GUI (Tkinter)
---------------------------------------
A simple GUI app to:
- Load a .txt or .html file (site dump / saved page)
- Define OUTPUT FIELDS (columns)
- For each field, add regex rules (extract/transform)
- Apply global cleaning rules (trim/collapse/max_len/drop patterns)
- Preview the first N rows
- Export to CSV
- Save/Load your rules as a JSON "profile"

How "regex rules" work (per field):
- Each field has an ordered list of rules.
- A rule is one of:
  1) EXTRACT: regex capture group -> becomes the field value
  2) REPLACE: regex substitution on the current field value
- You can chain multiple rules per field.

Requires for HTML input:
  pip install beautifulsoup4
"""

import csv
import json
import re
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Any

# -----------------------------
# Optional HTML -> text
# -----------------------------
def html_to_text(html: str) -> str:
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        raise ImportError("BeautifulSoup not installed. Run: pip install beautifulsoup4")
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "svg", "canvas"]):
        tag.decompose()
    return soup.get_text("\n")

def chunk_text(raw_text: str) -> List[str]:
    raw_text = raw_text.replace("\r\n", "\n").replace("\r", "\n")
    chunks = re.split(r"\n\s*\n+", raw_text)
    if len(chunks) == 1 and len(chunks[0]) > 20000:
        chunks = [c for c in raw_text.split("\n") if c.strip()]
    return [c.strip() for c in chunks if c and c.strip()]

# -----------------------------
# Rule Models
# -----------------------------
@dataclass
class FieldRule:
    kind: str            # "extract" or "replace"
    pattern: str
    repl: str = ""       # used for replace
    group: int = 1       # used for extract
    flags: str = "I"     # e.g. "I|M|S"

    def compile_flags(self) -> int:
        f = 0
        parts = [p.strip().upper() for p in self.flags.split("|") if p.strip()]
        for p in parts:
            if p == "I":
                f |= re.IGNORECASE
            elif p == "M":
                f |= re.MULTILINE
            elif p == "S":
                f |= re.DOTALL
        return f

@dataclass
class Profile:
    fields: List[str]
    field_rules: Dict[str, List[FieldRule]]
    # global cleaning:
    max_chars: int = 600
    min_chars: int = 40
    collapse_spaces: bool = True
    drop_patterns: List[str] = None  # patterns that drop an entire chunk

# -----------------------------
# Engine
# -----------------------------
def apply_global_cleaning(text: str, prof: Profile) -> str:
    s = text or ""
    if prof.collapse_spaces:
        s = re.sub(r"\s+", " ", s).strip()
    else:
        s = s.strip()

    # drop obvious junk by patterns
    if prof.drop_patterns:
        for pat in prof.drop_patterns:
            if not pat.strip():
                continue
            if re.search(pat, s, flags=re.IGNORECASE):
                return ""

    if len(s) < prof.min_chars:
        return ""

    if len(s) > prof.max_chars:
        # keep it simple: hard cut + ellipsis
        if prof.max_chars > 1:
            s = s[: prof.max_chars - 1] + "…"
        else:
            s = s[: prof.max_chars]
    return s

def run_cookie_cutter(input_path: str, prof: Profile) -> List[Dict[str, str]]:
    p = Path(input_path)
    raw = p.read_text(encoding="utf-8", errors="ignore")

    if p.suffix.lower() in (".html", ".htm"):
        raw = html_to_text(raw)

    chunks = chunk_text(raw)

    rows: List[Dict[str, str]] = []
    seen = set()

    for idx, chunk in enumerate(chunks, start=1):
        cleaned = apply_global_cleaning(chunk, prof)
        if not cleaned:
            continue

        key = cleaned.lower()
        if key in seen:
            continue
        seen.add(key)

        row: Dict[str, str] = {"source_file": p.name, "chunk_id": str(idx)}

        # field extraction per field
        for field in prof.fields:
            value = cleaned  # start from cleaned chunk for each field
            rules = prof.field_rules.get(field, [])

            for r in rules:
                try:
                    flags = r.compile_flags()
                    if r.kind == "extract":
                        m = re.search(r.pattern, value, flags=flags)
                        if not m:
                            value = ""
                        else:
                            # safe group access
                            try:
                                value = m.group(r.group)
                            except IndexError:
                                value = m.group(0)
                    elif r.kind == "replace":
                        value = re.sub(r.pattern, r.repl, value, flags=flags)
                    else:
                        # unknown rule kind
                        pass
                except re.error:
                    # invalid regex -> leave value as-is for now
                    continue

            row[field] = value.strip() if isinstance(value, str) else str(value)

        # convenience default description if user wants it:
        if "description" in prof.fields and not row.get("description"):
            row["description"] = cleaned

        rows.append(row)

    return rows

# -----------------------------
# GUI
# -----------------------------
class CookieCutterApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Site Cookie-Cutter (TXT/HTML → Structured CSV)")
        self.geometry("1100x700")

        self.input_path: Optional[str] = None
        self.preview_rows: List[Dict[str, str]] = []

        # in-app model
        self.fields: List[str] = ["title", "programme", "country", "url", "description"]
        self.field_rules: Dict[str, List[FieldRule]] = {f: [] for f in self.fields}

        self.max_chars_var = tk.IntVar(value=600)
        self.min_chars_var = tk.IntVar(value=40)
        self.collapse_spaces_var = tk.BooleanVar(value=True)

        self.drop_patterns: List[str] = [
            r"cookie\s+policy",
            r"accept\s+cookies",
            r"privacy\s+policy",
            r"terms\s+of\s+use",
        ]

        self._build_ui()

    def _build_ui(self):
        # Top controls
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Button(top, text="Load TXT/HTML", command=self.load_file).pack(side="left")
        self.file_label = ttk.Label(top, text="No file loaded")
        self.file_label.pack(side="left", padx=10)

        ttk.Button(top, text="Run Preview", command=self.run_preview).pack(side="left", padx=5)
        ttk.Button(top, text="Export CSV", command=self.export_csv).pack(side="left", padx=5)

        ttk.Button(top, text="Save Profile", command=self.save_profile).pack(side="right")
        ttk.Button(top, text="Load Profile", command=self.load_profile).pack(side="right", padx=5)

        # Main split
        main = ttk.Panedwindow(self, orient="horizontal")
        main.pack(fill="both", expand=True, padx=10, pady=10)

        left = ttk.Frame(main, padding=10)
        right = ttk.Frame(main, padding=10)
        main.add(left, weight=2)
        main.add(right, weight=3)

        # LEFT: Fields + Rules editor
        ttk.Label(left, text="Fields (CSV columns)", font=("Segoe UI", 10, "bold")).pack(anchor="w")

        fields_bar = ttk.Frame(left)
        fields_bar.pack(fill="x", pady=(5, 10))

        self.new_field_var = tk.StringVar()
        ttk.Entry(fields_bar, textvariable=self.new_field_var).pack(side="left", fill="x", expand=True)
        ttk.Button(fields_bar, text="Add Field", command=self.add_field).pack(side="left", padx=5)
        ttk.Button(fields_bar, text="Remove Field", command=self.remove_field).pack(side="left")

        self.fields_list = tk.Listbox(left, height=6)
        self.fields_list.pack(fill="x")
        for f in self.fields:
            self.fields_list.insert("end", f)
        self.fields_list.bind("<<ListboxSelect>>", lambda e: self.refresh_rules_list())

        ttk.Separator(left).pack(fill="x", pady=10)

        ttk.Label(left, text="Rules for selected field", font=("Segoe UI", 10, "bold")).pack(anchor="w")

        self.rules_list = tk.Listbox(left, height=10)
        self.rules_list.pack(fill="both", expand=True, pady=(5, 5))

        rules_btns = ttk.Frame(left)
        rules_btns.pack(fill="x")
        ttk.Button(rules_btns, text="Add Rule", command=self.add_rule_dialog).pack(side="left")
        ttk.Button(rules_btns, text="Edit Rule", command=self.edit_rule_dialog).pack(side="left", padx=5)
        ttk.Button(rules_btns, text="Delete Rule", command=self.delete_rule).pack(side="left", padx=5)
        ttk.Button(rules_btns, text="Move Up", command=lambda: self.move_rule(-1)).pack(side="right")
        ttk.Button(rules_btns, text="Move Down", command=lambda: self.move_rule(+1)).pack(side="right", padx=5)

        ttk.Separator(left).pack(fill="x", pady=10)

        # LEFT: Global cleaning controls
        ttk.Label(left, text="Global Cleaning (applies to every chunk)", font=("Segoe UI", 10, "bold")).pack(anchor="w")

        g = ttk.Frame(left)
        g.pack(fill="x", pady=5)
        ttk.Label(g, text="Max chars").grid(row=0, column=0, sticky="w")
        ttk.Entry(g, textvariable=self.max_chars_var, width=8).grid(row=0, column=1, sticky="w", padx=5)
        ttk.Label(g, text="Min chars").grid(row=0, column=2, sticky="w", padx=(15, 0))
        ttk.Entry(g, textvariable=self.min_chars_var, width=8).grid(row=0, column=3, sticky="w", padx=5)
        ttk.Checkbutton(g, text="Collapse spaces", variable=self.collapse_spaces_var).grid(row=1, column=0, columnspan=4, sticky="w", pady=(5, 0))

        ttk.Label(left, text="Drop patterns (one per line; regex):").pack(anchor="w", pady=(10, 0))
        self.drop_text = tk.Text(left, height=5)
        self.drop_text.pack(fill="x")
        self.drop_text.insert("1.0", "\n".join(self.drop_patterns))

        # RIGHT: Preview table
        ttk.Label(right, text="Preview (first rows)", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.preview = ttk.Treeview(right, columns=(), show="headings")
        self.preview.pack(fill="both", expand=True, pady=(5, 0))

        self.status = ttk.Label(self, text="Ready", relief="sunken", anchor="w")
        self.status.pack(fill="x", side="bottom")

        # Select first field by default
        if self.fields:
            self.fields_list.selection_set(0)
            self.refresh_rules_list()

    # ---------------- GUI actions ----------------
    def set_status(self, msg: str):
        self.status.config(text=msg)
        self.update_idletasks()

    def load_file(self):
        path = filedialog.askopenfilename(
            title="Select TXT or HTML file",
            filetypes=[("Text/HTML", "*.txt *.html *.htm"), ("All files", "*.*")]
        )
        if not path:
            return
        self.input_path = path
        self.file_label.config(text=Path(path).name)
        self.set_status(f"Loaded: {path}")

    def add_field(self):
        name = self.new_field_var.get().strip()
        if not name:
            return
        if name in self.fields:
            messagebox.showinfo("Field exists", f"'{name}' already exists.")
            return
        self.fields.append(name)
        self.field_rules[name] = []
        self.fields_list.insert("end", name)
        self.new_field_var.set("")
        self.set_status(f"Added field: {name}")
        self.refresh_preview_columns()

    def remove_field(self):
        sel = self._selected_field()
        if not sel:
            return
        if sel in ("source_file", "chunk_id"):
            messagebox.showwarning("Not allowed", "Cannot remove reserved fields.")
            return
        self.fields.remove(sel)
        self.field_rules.pop(sel, None)
        self._rebuild_fields_list()
        self.set_status(f"Removed field: {sel}")
        self.refresh_rules_list()
        self.refresh_preview_columns()

    def _rebuild_fields_list(self):
        self.fields_list.delete(0, "end")
        for f in self.fields:
            self.fields_list.insert("end", f)
        if self.fields:
            self.fields_list.selection_set(0)

    def _selected_field(self) -> Optional[str]:
        sel = self.fields_list.curselection()
        if not sel:
            return None
        return self.fields_list.get(sel[0])

    def refresh_rules_list(self):
        field = self._selected_field()
        self.rules_list.delete(0, "end")
        if not field:
            return
        rules = self.field_rules.get(field, [])
        for i, r in enumerate(rules, start=1):
            if r.kind == "extract":
                self.rules_list.insert("end", f"{i}. EXTRACT /{r.pattern}/ group={r.group} flags={r.flags}")
            else:
                self.rules_list.insert("end", f"{i}. REPLACE /{r.pattern}/ -> '{r.repl}' flags={r.flags}")

    def add_rule_dialog(self):
        field = self._selected_field()
        if not field:
            messagebox.showinfo("Select field", "Select a field first.")
            return
        RuleDialog(self, title=f"Add Rule → {field}", on_save=self._add_rule)

    def _add_rule(self, rule: FieldRule):
        field = self._selected_field()
        if not field:
            return
        self.field_rules[field].append(rule)
        self.refresh_rules_list()
        self.set_status(f"Added rule to {field}")

    def edit_rule_dialog(self):
        field = self._selected_field()
        if not field:
            return
        idx = self._selected_rule_index()
        if idx is None:
            messagebox.showinfo("Select rule", "Select a rule to edit.")
            return
        rule = self.field_rules[field][idx]
        RuleDialog(self, title=f"Edit Rule → {field}", on_save=lambda r: self._save_rule_edit(idx, r), initial=rule)

    def _save_rule_edit(self, idx: int, rule: FieldRule):
        field = self._selected_field()
        if not field:
            return
        self.field_rules[field][idx] = rule
        self.refresh_rules_list()
        self.set_status(f"Edited rule in {field}")

    def delete_rule(self):
        field = self._selected_field()
        if not field:
            return
        idx = self._selected_rule_index()
        if idx is None:
            return
        self.field_rules[field].pop(idx)
        self.refresh_rules_list()
        self.set_status(f"Deleted rule from {field}")

    def _selected_rule_index(self) -> Optional[int]:
        sel = self.rules_list.curselection()
        if not sel:
            return None
        return sel[0]

    def move_rule(self, delta: int):
        field = self._selected_field()
        if not field:
            return
        idx = self._selected_rule_index()
        if idx is None:
            return
        rules = self.field_rules[field]
        new_idx = idx + delta
        if new_idx < 0 or new_idx >= len(rules):
            return
        rules[idx], rules[new_idx] = rules[new_idx], rules[idx]
        self.refresh_rules_list()
        self.rules_list.selection_set(new_idx)

    def build_profile(self) -> Profile:
        # pull drop patterns from text box
        drops = [line.strip() for line in self.drop_text.get("1.0", "end").splitlines() if line.strip()]
        prof = Profile(
            fields=self.fields.copy(),
            field_rules={k: v.copy() for k, v in self.field_rules.items()},
            max_chars=int(self.max_chars_var.get()),
            min_chars=int(self.min_chars_var.get()),
            collapse_spaces=bool(self.collapse_spaces_var.get()),
            drop_patterns=drops
        )
        return prof

    def run_preview(self):
        if not self.input_path:
            messagebox.showinfo("No input", "Load a TXT/HTML file first.")
            return
        try:
            prof = self.build_profile()
            self.set_status("Running preview...")
            rows = run_cookie_cutter(self.input_path, prof)
            self.preview_rows = rows[:200]  # preview limit
            self.refresh_preview_table(self.preview_rows)
            self.set_status(f"Preview ready: {len(self.preview_rows)} rows (showing up to 200)")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.set_status("Error")

    def refresh_preview_columns(self):
        # rebuild columns for preview table
        cols = ["source_file", "chunk_id"] + self.fields
        self.preview["columns"] = cols
        for c in cols:
            self.preview.heading(c, text=c)
            self.preview.column(c, width=160, stretch=True)

    def refresh_preview_table(self, rows: List[Dict[str, str]]):
        self.refresh_preview_columns()
        self.preview.delete(*self.preview.get_children())
        cols = self.preview["columns"]
        for r in rows[:200]:
            values = [r.get(c, "") for c in cols]
            self.preview.insert("", "end", values=values)

    def export_csv(self):
        if not self.input_path:
            messagebox.showinfo("No input", "Load a TXT/HTML file first.")
            return
        save_path = filedialog.asksaveasfilename(
            title="Save CSV",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")]
        )
        if not save_path:
            return
        try:
            prof = self.build_profile()
            self.set_status("Exporting CSV...")
            rows = run_cookie_cutter(self.input_path, prof)
            cols = ["source_file", "chunk_id"] + prof.fields
            with open(save_path, "w", encoding="utf-8", newline="") as f:
                w = csv.DictWriter(f, fieldnames=cols)
                w.writeheader()
                for r in rows:
                    w.writerow({c: r.get(c, "") for c in cols})
            self.set_status(f"Exported: {save_path} ({len(rows)} rows)")
            messagebox.showinfo("Done", f"Exported {len(rows)} rows to:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.set_status("Error")

    def save_profile(self):
        path = filedialog.asksaveasfilename(
            title="Save profile JSON",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")]
        )
        if not path:
            return
        prof = self.build_profile()
        # serialize FieldRule objects
        payload = {
            "fields": prof.fields,
            "field_rules": {
                k: [asdict(r) for r in v] for k, v in prof.field_rules.items()
            },
            "max_chars": prof.max_chars,
            "min_chars": prof.min_chars,
            "collapse_spaces": prof.collapse_spaces,
            "drop_patterns": prof.drop_patterns or [],
        }
        Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self.set_status(f"Saved profile: {path}")

    def load_profile(self):
        path = filedialog.askopenfilename(
            title="Load profile JSON",
            filetypes=[("JSON", "*.json")]
        )
        if not path:
            return
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
            self.fields = payload.get("fields", [])
            fr = payload.get("field_rules", {})
            self.field_rules = {}
            for field in self.fields:
                self.field_rules[field] = [FieldRule(**d) for d in fr.get(field, [])]

            self.max_chars_var.set(int(payload.get("max_chars", 600)))
            self.min_chars_var.set(int(payload.get("min_chars", 40)))
            self.collapse_spaces_var.set(bool(payload.get("collapse_spaces", True)))

            drops = payload.get("drop_patterns", [])
            self.drop_text.delete("1.0", "end")
            self.drop_text.insert("1.0", "\n".join(drops))

            self._rebuild_fields_list()
            self.refresh_rules_list()
            self.refresh_preview_columns()
            self.set_status(f"Loaded profile: {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load profile:\n{e}")
            self.set_status("Error")

class RuleDialog(tk.Toplevel):
    def __init__(self, parent: CookieCutterApp, title: str, on_save, initial: Optional[FieldRule] = None):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.on_save = on_save

        self.kind_var = tk.StringVar(value=(initial.kind if initial else "extract"))
        self.pattern_var = tk.StringVar(value=(initial.pattern if initial else ""))
        self.repl_var = tk.StringVar(value=(initial.repl if initial else ""))
        self.group_var = tk.IntVar(value=(initial.group if initial else 1))
        self.flags_var = tk.StringVar(value=(initial.flags if initial else "I"))

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="Kind").grid(row=0, column=0, sticky="w")
        kind = ttk.Combobox(frm, textvariable=self.kind_var, values=["extract", "replace"], state="readonly", width=12)
        kind.grid(row=0, column=1, sticky="w")

        ttk.Label(frm, text="Pattern (regex)").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(frm, textvariable=self.pattern_var, width=60).grid(row=1, column=1, sticky="w", pady=(8, 0))

        ttk.Label(frm, text="Flags (I|M|S)").grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(frm, textvariable=self.flags_var, width=12).grid(row=2, column=1, sticky="w", pady=(8, 0))

        ttk.Label(frm, text="Group (extract)").grid(row=3, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(frm, textvariable=self.group_var, width=6).grid(row=3, column=1, sticky="w", pady=(8, 0))

        ttk.Label(frm, text="Replacement (replace)").grid(row=4, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(frm, textvariable=self.repl_var, width=60).grid(row=4, column=1, sticky="w", pady=(8, 0))

        btns = ttk.Frame(frm)
        btns.grid(row=5, column=0, columnspan=2, sticky="e", pady=(12, 0))

        ttk.Button(btns, text="Test Regex", command=self.test_regex).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Save", command=self.save).pack(side="left")
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="left", padx=(8, 0))

        # small help
        help_txt = (
            "EXTRACT: pattern searches current value; group picks capture group.\n"
            "REPLACE: pattern is substituted with 'Replacement'.\n"
            "Flags: I=ignorecase, M=multiline, S=dotall (use: I|S)."
        )
        ttk.Label(frm, text=help_txt, foreground="#666").grid(row=6, column=0, columnspan=2, sticky="w", pady=(10, 0))

        self.grab_set()

    def test_regex(self):
        pat = self.pattern_var.get()
        if not pat.strip():
            messagebox.showinfo("Test", "Enter a pattern first.")
            return
        # quick test on a sample string
        sample = "Example: MBA Programme in South Africa https://example.com/programmes/mba"
        try:
            flags = FieldRule(kind="extract", pattern=pat, flags=self.flags_var.get()).compile_flags()
            if self.kind_var.get() == "extract":
                m = re.search(pat, sample, flags=flags)
                if not m:
                    messagebox.showinfo("Test", "No match on sample text.")
                else:
                    g = int(self.group_var.get())
                    out = m.group(g) if g <= (m.lastindex or 0) else m.group(0)
                    messagebox.showinfo("Test", f"Matched:\n{out}")
            else:
                out = re.sub(pat, self.repl_var.get(), sample, flags=flags)
                messagebox.showinfo("Test", f"Result:\n{out}")
        except re.error as e:
            messagebox.showerror("Regex error", str(e))

    def save(self):
        kind = self.kind_var.get()
        pattern = self.pattern_var.get().strip()
        if not pattern:
            messagebox.showwarning("Missing", "Pattern is required.")
            return

        try:
            # validate regex
            flags = FieldRule(kind=kind, pattern=pattern, flags=self.flags_var.get()).compile_flags()
            re.compile(pattern, flags=flags)
        except re.error as e:
            messagebox.showerror("Regex error", str(e))
            return

        rule = FieldRule(
            kind=kind,
            pattern=pattern,
            repl=self.repl_var.get(),
            group=int(self.group_var.get()),
            flags=self.flags_var.get().strip() or "I"
        )
        self.on_save(rule)
        self.destroy()

# -----------------------------
# Run app
# -----------------------------
if __name__ == "__main__":
    app = CookieCutterApp()
    app.mainloop()
