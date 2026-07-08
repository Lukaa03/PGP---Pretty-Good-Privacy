import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog

from crypto import keys, signing, symmetric, message
from storage.keyring import PublicKeyRing, PrivateKeyRing

PRIVATE_RING_PATH = "private_ring.json"
PUBLIC_RING_PATH = "public_ring.json"

ALGO_CHOICES = [
    (symmetric.algo_name(symmetric.ALGO_AES128), symmetric.ALGO_AES128),
    (symmetric.algo_name(symmetric.ALGO_3DES), symmetric.ALGO_3DES),
]


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PGP aplikacija - Zastita podataka")
        self.geometry("860x560")
        self.private_ring = PrivateKeyRing(PRIVATE_RING_PATH)
        self.public_ring = PublicKeyRing(PUBLIC_RING_PATH)
        self._build_ui()
        self.refresh()

    def find_public_entry(self, key_id):
        e = self.public_ring.get_by_id(key_id)
        if e is None:
            e = self.private_ring.get_by_id(key_id)
        return e

    def _build_ui(self):
        bar = ttk.Frame(self, padding=(8, 6)); bar.pack(fill="x")
        ttk.Button(bar, text="Generisi par", command=self._generate).pack(side="left", padx=3)
        ttk.Button(bar, text="Uvezi .pem", command=self._import_pem).pack(side="left", padx=3)
        ttk.Button(bar, text="Posalji poruku", command=self._send).pack(side="left", padx=3)
        ttk.Button(bar, text="Primi poruku", command=self._receive).pack(side="left", padx=3)

        nb = ttk.Notebook(self); nb.pack(fill="both", expand=True, padx=8, pady=6)

        pf = ttk.Frame(nb); nb.add(pf, text="Prsten privatnih kljuceva")
        self.priv_tree = self._make_tree(pf)
        pb = ttk.Frame(pf, padding=(0, 6)); pb.pack(fill="x")
        ttk.Button(pb, text="Izvezi ceo par (.pem)", command=self._export_pair).pack(side="left", padx=3)
        ttk.Button(pb, text="Izvezi javni deo (.pem)", command=lambda: self._export_public("priv")).pack(side="left", padx=3)
        ttk.Button(pb, text="Obrisi", command=lambda: self._delete("priv")).pack(side="left", padx=3)

        uf = ttk.Frame(nb); nb.add(uf, text="Prsten javnih kljuceva")
        self.pub_tree = self._make_tree(uf)
        ub = ttk.Frame(uf, padding=(0, 6)); ub.pack(fill="x")
        ttk.Button(ub, text="Izvezi javni (.pem)", command=lambda: self._export_public("pub")).pack(side="left", padx=3)
        ttk.Button(ub, text="Obrisi", command=lambda: self._delete("pub")).pack(side="left", padx=3)

        self.status = ttk.Label(self, text="", relief="sunken", anchor="w", padding=4)
        self.status.pack(fill="x", side="bottom")

    def _make_tree(self, parent):
        cols = ("name", "email", "key_id", "size", "date")
        tree = ttk.Treeview(parent, columns=cols, show="headings", selectmode="browse")
        for c, t, w in [("name", "Ime", 150), ("email", "Mejl", 200),
                        ("key_id", "Key ID", 170), ("size", "Bita", 60), ("date", "Datum", 150)]:
            tree.heading(c, text=t); tree.column(c, width=w, anchor="w")
        tree.pack(fill="both", expand=True, side="left")
        sb = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        sb.pack(side="right", fill="y"); tree.configure(yscrollcommand=sb.set)
        return tree

    def refresh(self):
        for t in (self.priv_tree, self.pub_tree):
            for i in t.get_children(): t.delete(i)
        for e in self.private_ring.all():
            self.priv_tree.insert("", "end", iid=e["key_id"],
                                  values=(e["name"], e["email"], e["key_id"], e.get("key_size", ""), e["timestamp"]))
        for e in self.public_ring.all():
            self.pub_tree.insert("", "end", iid=e["key_id"],
                                 values=(e["name"], e["email"], e["key_id"], "-", e["timestamp"]))
        self.status.configure(text="Privatnih: %d   |   Javnih: %d"
                              % (len(self.private_ring.all()), len(self.public_ring.all())))

    def _selected(self, which):
        tree = self.priv_tree if which == "priv" else self.pub_tree
        ring = self.private_ring if which == "priv" else self.public_ring
        sel = tree.selection()
        if not sel:
            messagebox.showinfo("Info", "Prvo izaberite kljuc iz liste.", parent=self); return None
        return ring.get_by_id(sel[0])

    def _generate(self): KeyGenDialog(self)
    def _send(self): SendDialog(self)
    def _receive(self): ReceiveDialog(self)

    def _delete(self, which):
        e = self._selected(which)
        if not e: return
        if messagebox.askyesno("Brisanje", "Obrisati kljuc\n%s <%s>?" % (e["name"], e["email"]), parent=self):
            (self.private_ring if which == "priv" else self.public_ring).delete(e["key_id"])
            self.refresh()

    def _export_public(self, which):
        e = self._selected(which)
        if not e: return
        pub = keys.pem_to_public_key(e["public_pem"])
        path = filedialog.asksaveasfilename(title="Izvezi javni kljuc", defaultextension=".pem",
                                            initialfile="%s_public.pem" % e["email"],
                                            filetypes=[("PEM", "*.pem")], parent=self)
        if not path: return
        keys.export_public_pem(pub, path)
        messagebox.showinfo("Uspeh", "Javni kljuc izvezen:\n%s" % path, parent=self)

    def _export_pair(self):
        e = self._selected("priv")
        if not e: return
        pw = simpledialog.askstring("Lozinka", "Lozinka privatnog kljuca:", show="*", parent=self)
        if pw is None: return
        try:
            key = self.private_ring.load_private_key(e, pw)
        except Exception:
            messagebox.showerror("Greska", "Pogresna lozinka.", parent=self); return
        path = filedialog.asksaveasfilename(title="Izvezi par kljuceva", defaultextension=".pem",
                                            initialfile="%s_keypair.pem" % e["email"],
                                            filetypes=[("PEM", "*.pem")], parent=self)
        if not path: return
        keys.export_keypair_pem(key, path, pw)
        messagebox.showinfo("Uspeh", "Par kljuceva izvezen (sifrovan lozinkom):\n%s" % path, parent=self)

    def _import_pem(self):
        path = filedialog.askopenfilename(title="Uvezi .pem", filetypes=[("PEM", "*.pem"), ("Svi", "*.*")], parent=self)
        if not path: return
        try:
            kind, key = keys.import_pem(path)
        except (ValueError, TypeError):
            pw = simpledialog.askstring("Lozinka", "PEM je zasticen lozinkom, unesite je:", show="*", parent=self)
            if pw is None: return
            try:
                kind, key = keys.import_pem(path, passphrase=pw)
            except Exception:
                messagebox.showerror("Greska", "Neuspesan uvoz (pogresna lozinka ili fajl).", parent=self); return
        name = simpledialog.askstring("Podaci", "Ime vlasnika:", parent=self) or "nepoznato"
        email = simpledialog.askstring("Podaci", "Mejl vlasnika:", parent=self) or "nepoznato"
        if kind == "public":
            e = self.public_ring.add_public_key(key, name, email)
        else:
            npw = simpledialog.askstring("Lozinka", "Nova lozinka za cuvanje u prstenu:", show="*", parent=self)
            if not npw:
                messagebox.showwarning("Otkazano", "Lozinka je obavezna.", parent=self); return
            e = self.private_ring.add_imported_keypair(key, name, email, npw)
        self.refresh()
        messagebox.showinfo("Uspeh", "Uvezen %s kljuc. Key ID: %s" % (kind, e["key_id"]), parent=self)


class KeyGenDialog(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app); self.app = app
        self.title("Generisanje para kljuceva"); self.resizable(False, False); self.grab_set()
        f = ttk.Frame(self, padding=16); f.grid()
        self.name = tk.StringVar(); self.email = tk.StringVar()
        self.size = tk.IntVar(value=2048); self.pw = tk.StringVar(); self.pw2 = tk.StringVar()
        ttk.Label(f, text="Ime:").grid(row=0, column=0, sticky="w", pady=3)
        ttk.Entry(f, textvariable=self.name, width=30).grid(row=0, column=1, pady=3)
        ttk.Label(f, text="Mejl:").grid(row=1, column=0, sticky="w", pady=3)
        ttk.Entry(f, textvariable=self.email, width=30).grid(row=1, column=1, pady=3)
        ttk.Label(f, text="Velicina:").grid(row=2, column=0, sticky="w", pady=3)
        sf = ttk.Frame(f); sf.grid(row=2, column=1, sticky="w")
        ttk.Radiobutton(sf, text="1024", variable=self.size, value=1024).pack(side="left")
        ttk.Radiobutton(sf, text="2048", variable=self.size, value=2048).pack(side="left", padx=10)
        ttk.Label(f, text="Lozinka:").grid(row=3, column=0, sticky="w", pady=3)
        ttk.Entry(f, textvariable=self.pw, show="*", width=30).grid(row=3, column=1, pady=3)
        ttk.Label(f, text="Potvrda:").grid(row=4, column=0, sticky="w", pady=3)
        ttk.Entry(f, textvariable=self.pw2, show="*", width=30).grid(row=4, column=1, pady=3)
        bf = ttk.Frame(f); bf.grid(row=5, column=0, columnspan=2, pady=(12, 0))
        ttk.Button(bf, text="Generisi", command=self._go).pack(side="left", padx=6)
        ttk.Button(bf, text="Otkazi", command=self.destroy).pack(side="left", padx=6)

    def _go(self):
        if not self.name.get().strip() or not self.email.get().strip():
            messagebox.showwarning("Nedostaje", "Unesite ime i mejl.", parent=self); return
        if not self.pw.get():
            messagebox.showwarning("Nedostaje", "Unesite lozinku.", parent=self); return
        if self.pw.get() != self.pw2.get():
            messagebox.showerror("Greska", "Lozinke se ne poklapaju.", parent=self); return
        try:
            e = self.app.private_ring.add_new_keypair(self.name.get().strip(), self.email.get().strip(),
                                                      self.size.get(), self.pw.get())
        except Exception as ex:
            messagebox.showerror("Greska", str(ex), parent=self); return
        self.app.refresh()
        messagebox.showinfo("Uspeh", "Generisan par. Key ID: %s" % e["key_id"], parent=self)
        self.destroy()


class SendDialog(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app); self.app = app
        self.title("Slanje poruke"); self.grab_set(); self.source_file = None
        f = ttk.Frame(self, padding=14); f.pack(fill="both", expand=True)
        ttk.Label(f, text="Poruka:", font=("", 10, "bold")).grid(row=0, column=0, sticky="w")
        self.text = tk.Text(f, width=56, height=7); self.text.grid(row=1, column=0, columnspan=3, pady=4)
        ttk.Button(f, text="...ili ucitaj fajl", command=self._load_file).grid(row=2, column=0, sticky="w")
        self.file_lbl = ttk.Label(f, text="", foreground="#177245"); self.file_lbl.grid(row=2, column=1, columnspan=2, sticky="w")
        ttk.Separator(f, orient="horizontal").grid(row=3, column=0, columnspan=3, sticky="ew", pady=8)
        self.v_sign = tk.BooleanVar(); self.v_enc = tk.BooleanVar()
        self.v_comp = tk.BooleanVar(); self.v_r64 = tk.BooleanVar()
        ttk.Checkbutton(f, text="Potpisi", variable=self.v_sign, command=self._refresh).grid(row=4, column=0, sticky="w")
        ttk.Checkbutton(f, text="Sifruj", variable=self.v_enc, command=self._refresh).grid(row=4, column=1, sticky="w")
        ttk.Checkbutton(f, text="Kompresuj", variable=self.v_comp).grid(row=5, column=0, sticky="w")
        ttk.Checkbutton(f, text="Radix-64", variable=self.v_r64).grid(row=5, column=1, sticky="w")
        ttk.Separator(f, orient="horizontal").grid(row=6, column=0, columnspan=3, sticky="ew", pady=8)
        ttk.Label(f, text="Privatni kljuc (potpis):").grid(row=7, column=0, sticky="w", pady=2)
        self.cb_sign = ttk.Combobox(f, width=44, state="readonly"); self.cb_sign.grid(row=7, column=1, columnspan=2, sticky="w")
        ttk.Label(f, text="Javni kljuc primaoca:").grid(row=8, column=0, sticky="w", pady=2)
        self.cb_rec = ttk.Combobox(f, width=44, state="readonly"); self.cb_rec.grid(row=8, column=1, columnspan=2, sticky="w")
        ttk.Label(f, text="Simetricni algoritam:").grid(row=9, column=0, sticky="w", pady=2)
        self.cb_algo = ttk.Combobox(f, width=20, state="readonly", values=[n for n, _ in ALGO_CHOICES])
        self.cb_algo.current(0); self.cb_algo.grid(row=9, column=1, sticky="w")
        bf = ttk.Frame(f); bf.grid(row=10, column=0, columnspan=3, pady=(12, 0))
        ttk.Button(bf, text="Sacuvaj poruku (.pgp)", command=self._send).pack(side="left", padx=6)
        ttk.Button(bf, text="Zatvori", command=self.destroy).pack(side="left", padx=6)
        self._fill(); self._refresh()

    def _fill(self):
        self._priv = {}; self._pub = {}; pv = []
        for e in self.app.private_ring.all():
            lbl = "%s <%s>  [%s]" % (e["name"], e["email"], e["key_id"]); pv.append(lbl); self._priv[lbl] = e
        self.cb_sign["values"] = pv
        if pv: self.cb_sign.current(0)
        rv = []; seen = set()
        for e in list(self.app.public_ring.all()) + list(self.app.private_ring.all()):
            if e["key_id"] in seen: continue
            seen.add(e["key_id"])
            lbl = "%s <%s>  [%s]" % (e["name"], e["email"], e["key_id"]); rv.append(lbl); self._pub[lbl] = e
        self.cb_rec["values"] = rv
        if rv: self.cb_rec.current(0)

    def _refresh(self):
        self.cb_sign.configure(state="readonly" if self.v_sign.get() else "disabled")
        st = "readonly" if self.v_enc.get() else "disabled"
        self.cb_rec.configure(state=st); self.cb_algo.configure(state=st)

    def _load_file(self):
        p = filedialog.askopenfilename(title="Fajl za slanje", parent=self)
        if p: self.source_file = p; self.file_lbl.configure(text=os.path.basename(p))

    def _send(self):
        if self.source_file:
            with open(self.source_file, "rb") as fh: data = fh.read()
            filename = os.path.basename(self.source_file)
        else:
            txt = self.text.get("1.0", "end-1c")
            if not txt:
                messagebox.showwarning("Prazno", "Unesite tekst ili ucitajte fajl.", parent=self); return
            data = txt.encode("utf-8"); filename = "poruka.txt"
        sign_priv = sender_kid = enc_pub = recipient_kid = algo = None
        if self.v_sign.get():
            lbl = self.cb_sign.get()
            if not lbl:
                messagebox.showwarning("Nema kljuca", "Izaberite privatni kljuc.", parent=self); return
            e = self._priv[lbl]
            pw = simpledialog.askstring("Lozinka", "Lozinka za %s <%s>:" % (e["name"], e["email"]), show="*", parent=self)
            if pw is None: return
            try:
                sign_priv = self.app.private_ring.load_private_key(e, pw)
            except Exception:
                messagebox.showerror("Greska", "Pogresna lozinka.", parent=self); return
            sender_kid = e["key_id"]
        if self.v_enc.get():
            lbl = self.cb_rec.get()
            if not lbl:
                messagebox.showwarning("Nema kljuca", "Izaberite javni kljuc primaoca.", parent=self); return
            e = self._pub[lbl]
            enc_pub = keys.pem_to_public_key(e["public_pem"]); recipient_kid = e["key_id"]
            algo = dict(ALGO_CHOICES)[self.cb_algo.get()]
        try:
            raw = message.build_message(data, filename=filename,
                                        sign_priv=sign_priv, sender_key_id=sender_kid,
                                        enc_pub=enc_pub, recipient_key_id=recipient_kid, algo=algo,
                                        compress=self.v_comp.get(), radix64=self.v_r64.get())
        except Exception as ex:
            messagebox.showerror("Greska pri sklapanju", str(ex), parent=self); return
        path = filedialog.asksaveasfilename(title="Sacuvaj poruku", defaultextension=".pgp",
                                            filetypes=[("PGP poruka", "*.pgp"), ("Svi", "*.*")], parent=self)
        if not path: return
        with open(path, "wb") as fh: fh.write(raw)
        messagebox.showinfo("Uspeh", "Poruka sacuvana:\n%s" % path, parent=self)
        self.destroy()


class ReceiveDialog(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app); self.app = app
        self.title("Prijem poruke"); self.grab_set(); self.result = None
        f = ttk.Frame(self, padding=14); f.pack(fill="both", expand=True)
        top = ttk.Frame(f); top.pack(fill="x")
        ttk.Button(top, text="Otvori .pgp poruku...", command=self._open).pack(side="left")
        self.file_lbl = ttk.Label(top, text="(nije izabran fajl)", foreground="#555"); self.file_lbl.pack(side="left", padx=10)
        ttk.Separator(f, orient="horizontal").pack(fill="x", pady=8)
        ttk.Label(f, text="Status:", font=("", 10, "bold")).pack(anchor="w")
        self.out = tk.Text(f, width=64, height=12, state="disabled", wrap="word"); self.out.pack(pady=4)
        bf = ttk.Frame(f); bf.pack(pady=(6, 0))
        self.save_btn = ttk.Button(bf, text="Sacuvaj originalnu poruku...", command=self._save, state="disabled")
        self.save_btn.pack(side="left", padx=6)
        ttk.Button(bf, text="Zatvori", command=self.destroy).pack(side="left", padx=6)

    def _open(self):
        path = filedialog.askopenfilename(title="Izaberi .pgp", filetypes=[("PGP poruka", "*.pgp"), ("Svi", "*.*")], parent=self)
        if not path: return
        self.file_lbl.configure(text=os.path.basename(path))
        with open(path, "rb") as fh: raw = fh.read()
        private_key = None
        try:
            recip_id = message.read_recipient_key_id(raw)
        except Exception:
            self._show("GRESKA: fajl nije prepoznatljiva PGP poruka.", err=True); return
        if recip_id is not None:
            entry = self.app.private_ring.get_by_id(recip_id)
            if entry is None:
                self._show("GRESKA: poruka je sifrovana za Key ID %s,\nali taj privatni kljuc nije u prstenu." % recip_id, err=True); return
            pw = simpledialog.askstring("Lozinka", "Lozinka za %s <%s>:" % (entry["name"], entry["email"]), show="*", parent=self)
            if pw is None: return
            try:
                private_key = self.app.private_ring.load_private_key(entry, pw)
            except Exception:
                self._show("GRESKA: pogresna lozinka za privatni kljuc.", err=True); return
        try:
            res = message.parse_message(raw, private_key=private_key)
        except Exception as ex:
            self._show("GRESKA pri obradi poruke:\n%s" % ex, err=True); return
        self.result = res
        self._show_result(res)
        self.save_btn.configure(state="normal")

    def _show_result(self, res):
        lines = []
        lines.append("Fajl:       %s" % res.get("filename"))
        lines.append("Kreirano:   %s" % res.get("timestamp"))
        lines.append("Sifrovano:  %s" % ("DA" if res["encrypted"] else "NE"))
        lines.append("Kompresija: %s" % ("DA" if res["compressed"] else "NE"))
        lines.append("Radix-64:   %s" % ("DA" if res["radix64"] else "NE"))
        lines.append("")
        if res["signed"]:
            entry = self.app.find_public_entry(res.get("sender_key_id"))
            if entry is None:
                lines.append(">> POTPIS: autor NEPOZNAT (Key ID %s nije u prstenu)" % res.get("sender_key_id"))
            else:
                pub = keys.pem_to_public_key(entry["public_pem"])
                ok = signing.verify_mess(res["data"], res["signature"], pub)
                if ok:
                    lines.append(">> POTPIS VALIDAN")
                    lines.append("   Autor: %s <%s>" % (entry["name"], entry["email"]))
                else:
                    lines.append(">> POTPIS NEISPRAVAN!")
        else:
            lines.append("Poruka nije potpisana.")
        lines.append("")
        try:
            preview = res["data"].decode("utf-8")
            lines.append("--- Sadrzaj ---"); lines.append(preview[:3000])
        except UnicodeDecodeError:
            lines.append("(binarni sadrzaj - sacuvajte ga u fajl)")
        self._show("\n".join(lines))

    def _show(self, text, err=False):
        self.out.configure(state="normal"); self.out.delete("1.0", "end"); self.out.insert("1.0", text)
        self.out.tag_configure("e", foreground="#b00020")
        if err: self.out.tag_add("e", "1.0", "end")
        self.out.configure(state="disabled")

    def _save(self):
        if not self.result: return
        default = self.result.get("filename") or "poruka.txt"
        path = filedialog.asksaveasfilename(title="Sacuvaj poruku", initialfile=default, parent=self)
        if not path: return
        with open(path, "wb") as fh: fh.write(self.result["data"])
        messagebox.showinfo("Uspeh", "Sacuvano:\n%s" % path, parent=self)


def run():
    MainWindow().mainloop()