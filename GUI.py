#!/usr/bin/env python3
"""
gui.py - Combined GUI for secure_image.exe (encrypt/decrypt) + PSNR/SSIM integrity checks.

Usage during development:
    python gui.py

When bundled with PyInstaller (see bottom of the file comments), secure_image.exe
is included inside the single EXE and discovered automatically.
"""

import os
import sys
import threading
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

# Optional: image preview (Pillow)
from PIL import Image, ImageTk

# OpenCV + skimage for PSNR / SSIM
import cv2
from skimage.metrics import structural_similarity as ssim

# ---------------------------
# Helpers
# ---------------------------
def get_bundled_exe_name():
    """Return expected secure_image exe filename (platform-specific)."""
    return "secure_image.exe"

def find_secure_exe():
    """
    If running packaged by PyInstaller, the binary will be in sys._MEIPASS.
    Otherwise look in the current script folder or a user-selected path.
    """
    exe_name = get_bundled_exe_name()
    # If running from a PyInstaller bundle
    if getattr(sys, "_MEIPASS", None):
        candidate = os.path.join(sys._MEIPASS, exe_name)
        if os.path.isfile(candidate):
            return candidate
    # Check current script directory
    script_dir = os.path.abspath(os.path.dirname(__file__))
    candidate = os.path.join(script_dir, exe_name)
    if os.path.isfile(candidate):
        return candidate
    # Not found automatically
    return ""

def is_exe_ok(path: str) -> bool:
    return bool(path) and os.path.isfile(path) and os.access(path, os.X_OK)

def safe_cmd_join(cmd_list):
    """Return printable command for logging (escapes spaces)."""
    return " ".join([f'"{p}"' if " " in p else p for p in cmd_list])

# ---------------------------
# GUI App
# ---------------------------
class SecureImageApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SecureImage Tool - Encrypt / Decrypt / Verify")
        self.geometry("900x640")
        self.resizable(True, True)

        # Paths
        self.exe_path = find_secure_exe()
        self.input_path = ""
        self.packet_path = ""
        self.output_path = ""

        # UI
        self._build_ui()

    def _build_ui(self):
        pad = 8

        # Top frame for exe path
        f_exe = tk.Frame(self)
        f_exe.pack(fill="x", padx=pad, pady=(pad, 2))
        tk.Label(f_exe, text="secure_image executable:").pack(side="left")
        self.exe_entry = tk.Entry(f_exe, width=80)
        self.exe_entry.pack(side="left", padx=(6,6))
        if self.exe_path:
            self.exe_entry.insert(0, self.exe_path)
        tk.Button(f_exe, text="Browse", command=self.browse_exe).pack(side="left", padx=(6,0))

        # Row: Input image / packet / output
        f_row = tk.Frame(self)
        f_row.pack(fill="x", padx=pad, pady=6)

        # Input
        li = tk.LabelFrame(f_row, text="Input (image for encrypt / packet for decrypt)")
        li.pack(fill="x", padx=4, pady=4)
        self.input_entry = tk.Entry(li, width=100)
        self.input_entry.pack(side="left", padx=(6,6), pady=6)
        tk.Button(li, text="Browse Image", command=self.browse_input_image).pack(side="left", padx=6)
        tk.Button(li, text="Browse Packet", command=self.browse_packet_for_input).pack(side="left", padx=6)

        # Packet path (save)
        lp = tk.LabelFrame(self, text="Packet (JSON)")
        lp.pack(fill="x", padx=4, pady=4)
        self.packet_entry = tk.Entry(lp, width=100)
        self.packet_entry.pack(side="left", padx=(6,6), pady=6)
        tk.Button(lp, text="Save As Packet", command=self.browse_packet).pack(side="left", padx=6)

        # Output path (for decrypt output)
        lo = tk.LabelFrame(self, text="Output Image (decrypted)")
        lo.pack(fill="x", padx=4, pady=4)
        self.output_entry = tk.Entry(lo, width=100)
        self.output_entry.pack(side="left", padx=(6,6), pady=6)
        tk.Button(lo, text="Browse Output", command=self.browse_output).pack(side="left", padx=6)

        # Buttons row
        f_buttons = tk.Frame(self)
        f_buttons.pack(fill="x", padx=pad, pady=10)
        tk.Button(f_buttons, text="Encrypt", width=14, command=self.encrypt_click).pack(side="left", padx=6)
        tk.Button(f_buttons, text="Decrypt", width=14, command=self.decrypt_click).pack(side="left", padx=6)
        tk.Button(f_buttons, text="Check Integrity (PSNR/SSIM)", width=20, command=self.check_integrity).pack(side="left", padx=6)
        tk.Button(f_buttons, text="Open Output Folder", command=self.open_output_folder).pack(side="left", padx=6)
        tk.Button(f_buttons, text="Clear Log", command=self.clear_log).pack(side="right", padx=6)

        # Main area: log + preview
        main_frame = tk.Frame(self)
        main_frame.pack(fill="both", expand=True, padx=pad, pady=(0,pad))

        # Log (left)
        log_frame = tk.Frame(main_frame)
        log_frame.pack(side="left", fill="both", expand=True)
        tk.Label(log_frame, text="Log").pack(anchor="w")
        self.log = scrolledtext.ScrolledText(log_frame, height=20)
        self.log.pack(fill="both", expand=True)

        # Preview (right)
        preview_frame = tk.Frame(main_frame, width=300)
        preview_frame.pack(side="right", fill="y")
        tk.Label(preview_frame, text="Preview (original | decrypted)").pack()
        self.preview_orig = tk.Label(preview_frame)
        self.preview_orig.pack(pady=6)
        self.preview_dec = tk.Label(preview_frame)
        self.preview_dec.pack(pady=6)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(self, textvariable=self.status_var, anchor="w")
        status_bar.pack(fill="x", side="bottom")

    # -----------------------
    # Browsers
    # -----------------------
    def browse_exe(self):
        p = filedialog.askopenfilename(title="Select secure_image executable",
                                       filetypes=[("Executable","*.exe"), ("All files","*.*")])
        if p:
            self.exe_path = p
            self.exe_entry.delete(0, tk.END)
            self.exe_entry.insert(0, p)

    def browse_input_image(self):
        p = filedialog.askopenfilename(title="Select image to encrypt",
                                       filetypes=[("Images","*.png;*.jpg;*.jpeg;*.bmp;*.gif"), ("All files","*.*")])
        if p:
            self.input_path = p
            self.input_entry.delete(0, tk.END)
            self.input_entry.insert(0, p)
            self._preview_image(p, which="orig")

    def browse_packet_for_input(self):
        # if the user wants to decrypt, they might choose a packet as the input
        p = filedialog.askopenfilename(title="Select packet.json to decrypt",
                                       filetypes=[("JSON","*.json"), ("All files","*.*")])
        if p:
            self.input_path = p
            self.input_entry.delete(0, tk.END)
            self.input_entry.insert(0, p)

    def browse_packet(self):
        p = filedialog.asksaveasfilename(title="Select or create packet file (JSON)", defaultextension=".json",
                                         filetypes=[("JSON","*.json"), ("All files","*.*")])
        if p:
            self.packet_path = p
            self.packet_entry.delete(0, tk.END)
            self.packet_entry.insert(0, p)

    def browse_output(self):
        p = filedialog.asksaveasfilename(title="Select output image path", defaultextension=".png",
                                         filetypes=[("PNG","*.png"), ("JPEG","*.jpg;*.jpeg"), ("All files","*.*")])
        if p:
            self.output_path = p
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, p)
            # preview output if exists
            if os.path.isfile(p):
                self._preview_image(p, which="dec")

    # -----------------------
    # UI helpers
    # -----------------------
    def log_msg(self, text: str):
        self.log.insert("end", text + "\n")
        self.log.see("end")

    def set_status(self, text: str):
        self.status_var.set(text)

    def clear_log(self):
        self.log.delete("1.0", "end")

    def open_output_folder(self):
        path = self.output_entry.get().strip()
        if not path:
            messagebox.showinfo("Open folder", "Set an output file first.")
            return
        folder = os.path.abspath(os.path.dirname(path))
        if not os.path.isdir(folder):
            messagebox.showerror("Open folder", f"Folder doesn't exist: {folder}")
            return
        if sys.platform.startswith("win"):
            os.startfile(folder)
        else:
            subprocess.Popen(["xdg-open", folder])

    def _preview_image(self, path, which="orig"):
        try:
            img = Image.open(path)
            img.thumbnail((260, 260))
            tkimg = ImageTk.PhotoImage(img)
            if which == "orig":
                self.preview_orig.configure(image=tkimg)
                self.preview_orig.image = tkimg
            else:
                self.preview_dec.configure(image=tkimg)
                self.preview_dec.image = tkimg
        except Exception as e:
            # ignore preview errors but log
            self.log_msg(f"[WARN] preview failed: {e}")

    # -----------------------
    # Execution (threaded)
    # -----------------------
    def run_command_threaded(self, args, on_success_callback=None):
        t = threading.Thread(target=self._run_command, args=(args, on_success_callback), daemon=True)
        t.start()

    def _resolve_exe(self):
        # from UI entry or auto-find within bundle
        exe = self.exe_entry.get().strip()
        if not exe:
            exe = self.exe_path or find_secure_exe()
        # if running from PyInstaller single-file, the exe is bundled under _MEIPASS
        if not os.path.isabs(exe) and getattr(sys, "_MEIPASS", None):
            possible = os.path.join(sys._MEIPASS, get_bundled_exe_name())
            if os.path.isfile(possible):
                exe = possible
        return exe

    def _run_command(self, args, on_success_callback):
        exe = self._resolve_exe()
        if not is_exe_ok(exe):
            self.log_msg(f"[ERROR] secure_image executable not found or not executable: {exe}")
            self.set_status("Executable missing")
            return

        cmd = [exe] + args
        self.log_msg(f"> {safe_cmd_join(cmd)}")
        self.set_status("Running...")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False)
            out, err = proc.communicate()
            if out:
                self.log_msg(out.strip())
            if err:
                self.log_msg("[stderr] " + err.strip())
            rc = proc.returncode
            self.log_msg(f"[PROCESS EXIT CODE] {rc}")
            if rc == 0:
                self.set_status("Completed")
                # run on_success callback if provided (UI thread)
                if on_success_callback:
                    self.after(100, on_success_callback)
            else:
                self.set_status(f"Failed (code {rc})")
        except Exception as e:
            self.log_msg(f"[EXCEPTION] {e}")
            self.set_status("Error")

    # -----------------------
    # Button handlers
    # -----------------------
    def encrypt_click(self):
        input_path = self.input_entry.get().strip()
        packet_path = self.packet_entry.get().strip()
        if not input_path or not os.path.isfile(input_path):
            messagebox.showwarning("Missing input", "Choose a valid input image to encrypt.")
            return
        if not packet_path:
            messagebox.showwarning("Missing packet", "Choose where to save the packet.json.")
            return
        args = ["encrypt", input_path, packet_path]
        self.log_msg("[ACTION] Encrypting...")
        # after encryption we don't auto-run integrity (no output image yet)
        self.run_command_threaded(args, on_success_callback=None)

    def decrypt_click(self):
        packet_path = self.packet_entry.get().strip()
        output_path = self.output_entry.get().strip()
        if not packet_path or not os.path.isfile(packet_path):
            messagebox.showwarning("Missing packet", "Choose a valid packet.json to decrypt.")
            return
        if not output_path:
            messagebox.showwarning("Missing output", "Choose an output image path.")
            return
        args = ["decrypt", packet_path, output_path]
        self.log_msg("[ACTION] Decrypting...")
        # after successful decrypt, auto-run integrity check
        self.run_command_threaded(args, on_success_callback=self._after_decrypt_hook)

    def _after_decrypt_hook(self):
        # show preview of decrypted file if it exists and then run integrity check
        outp = self.output_entry.get().strip()
        if os.path.isfile(outp):
            self._preview_image(outp, which="dec")
        # auto-check integrity (runs in GUI thread, will call OpenCV)
        try:
            self.check_integrity()
        except Exception as e:
            self.log_msg(f"[WARN] auto integrity failed: {e}")

    # -----------------------
    # Integrity check (PSNR + SSIM)
    # -----------------------
    def check_integrity(self):
        orig = self.input_entry.get().strip()
        dec  = self.output_entry.get().strip()

        if not orig or not os.path.isfile(orig):
            messagebox.showwarning("Missing original", "Select a valid ORIGINAL image.")
            return
        if not dec or not os.path.isfile(dec):
            messagebox.showwarning("Missing decrypted", "Select a valid DECRYPTED image.")
            return

        self.log_msg("[ACTION] Computing PSNR and SSIM...")
        self.set_status("Computing metrics...")

        # load images using OpenCV
        img1 = cv2.imread(orig)
        img2 = cv2.imread(dec)

        if img1 is None or img2 is None:
            self.log_msg("[ERROR] Could not read one of the images.")
            self.set_status("Error")
            return

        # Resize decrypted if needed (but log this)
        if img1.shape != img2.shape:
            self.log_msg("[WARN] Image sizes differ. Resizing decrypted image.")
            img2 = cv2.resize(img2, (img1.shape[1], img1.shape[0]))

        # PSNR
        try:
            psnr_val = cv2.PSNR(img1, img2)
        except Exception as e:
            self.log_msg(f"[ERROR] PSNR calculation failed: {e}")
            self.set_status("Error")
            return

        # SSIM (grayscale)
        try:
            gray1 = cv2.cvtColor(img1, cv2.COLOR_BGR2GRAY)
            gray2 = cv2.cvtColor(img2, cv2.COLOR_BGR2GRAY)
            ssim_val, _ = ssim(gray1, gray2, full=True)
        except Exception as e:
            self.log_msg(f"[ERROR] SSIM calculation failed: {e}")
            self.set_status("Error")
            return

        # Log
        self.log_msg("------ INTEGRITY REPORT ------")
        self.log_msg(f"PSNR : {psnr_val:.4f} dB")
        self.log_msg(f"SSIM : {ssim_val:.6f}")
        if psnr_val > 40 and ssim_val > 0.95:
            self.log_msg("Integrity: PASS (Images are identical)")
            result_str = "PASS"
        else:
            self.log_msg("Integrity: FAIL (Images differ)")
            result_str = "FAIL"

        self.set_status("Metrics computed")

        # save report
        try:
            report_path = os.path.join(os.path.dirname(dec), "integrity_report.txt")
            with open(report_path, "a", encoding="utf-8") as r:
                r.write("==== Integrity report ====\n")
                r.write(f"Original: {orig}\n")
                r.write(f"Decrypted: {dec}\n")
                r.write(f"PSNR: {psnr_val:.4f} dB\n")
                r.write(f"SSIM: {ssim_val:.6f}\n")
                r.write(f"Result: {result_str}\n\n")
            self.log_msg(f"[INFO] Report saved to: {report_path}")
        except Exception as e:
            self.log_msg(f"[WARN] Could not save report: {e}")

# ---------------------------
# Run the app
# ---------------------------
if __name__ == "__main__":
    app = SecureImageApp()
    app.mainloop()
