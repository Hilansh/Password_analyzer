"""Tkinter graphical interface; no third-party packages required."""
import tkinter as tk
from tkinter import ttk, messagebox
from .analyzer import analyze_password

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Analyzer")
        self.geometry("760x620")
        self.minsize(620, 520)
        self.configure(padx=18, pady=16)
        ttk.Label(self, text="Password Analyzer", font=("Segoe UI", 20, "bold")).pack(anchor="w")
        ttk.Label(self, text="Offline password assessment • Your password is not stored or transmitted").pack(anchor="w", pady=(2,14))
        row = ttk.Frame(self); row.pack(fill="x")
        self.password = tk.StringVar()
        self.entry = ttk.Entry(row, textvariable=self.password, show="•", font=("Consolas", 12))
        self.entry.pack(side="left", fill="x", expand=True)
        self.show = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text="Show", variable=self.show, command=self.toggle).pack(side="left", padx=8)
        ttk.Label(self, text="Optional context words (e.g. username, service, organisation), comma-separated:").pack(anchor="w", pady=(12,3))
        self.context = tk.StringVar()
        ttk.Entry(self, textvariable=self.context).pack(fill="x")
        ttk.Button(self, text="Analyze Password", command=self.analyze).pack(anchor="w", pady=12)
        self.result = ttk.Label(self, text="Enter a password and select Analyze.", font=("Segoe UI", 14, "bold"))
        self.result.pack(anchor="w")
        self.progress = ttk.Progressbar(self, maximum=100, length=400)
        self.progress.pack(fill="x", pady=7)
        self.details = tk.Text(self, height=20, wrap="word", font=("Segoe UI", 10), state="disabled")
        self.details.pack(fill="both", expand=True)
        self.entry.focus_set()
        self.bind("<Return>", lambda _e: self.analyze())

    def toggle(self):
        self.entry.configure(show="" if self.show.get() else "•")

    def analyze(self):
        pw = self.password.get()
        if not pw:
            messagebox.showinfo("Password Analyzer", "Please enter a password.")
            return
        context = [x.strip() for x in self.context.get().split(",") if x.strip()]
        r = analyze_password(pw, context)
        self.result.configure(text=f"{r.rating} — {r.score}/100")
        self.progress["value"] = r.score
        lines = [f"Length: {r.length}", f"Estimated character-pool entropy: {r.entropy_bits} bits (rough upper-bound only)",
                 "", "CHARACTER TYPES"]
        lines += [f"  {k.title()}: {'Yes' if v else 'No'}" for k,v in r.character_types.items()]
        lines += ["", "FINDINGS"] + [f"  • {x}" for x in r.findings]
        lines += ["", "RECOMMENDATIONS"] + [f"  • {x}" for x in r.recommendations]
        lines += ["", "Note: composition diversity is descriptive, not a mandatory rule. Entropy is not a reliable estimate of human password guessability."]
        self.details.configure(state="normal"); self.details.delete("1.0", "end")
        output = "\n".join(lines)
        output = output.replace("\\n", "\n")
        self.details.insert("1.0", output)
        self.details.configure(state="disabled")
        self.password.set("")  # avoid leaving the secret in the input after analysis

def main():
    App().mainloop()
if __name__ == "__main__": main()
