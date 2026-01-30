# Cookie_Cutter_DataCleaner

The vision is to create a robust filtration system to help extract KPIs in unstructured data.


GUIDE:
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
