import tkinter as tk
from tkinter import filedialog, messagebox
import requests
import os
import base64
import re
import csv
from openpyxl import Workbook
from dotenv import load_dotenv
 
# === API ve Global Ayarlar === #
load_dotenv()
API_KEY = os.getenv("VT_API_KEY")
 
VT_URLS = {
    'SHA-256': 'https://www.virustotal.com/api/v3/files/',
    'SHA-1': 'https://www.virustotal.com/api/v3/files/',
    'MD5': 'https://www.virustotal.com/api/v3/files/',
    'Domain': 'https://www.virustotal.com/api/v3/domains/',
    'URL': 'https://www.virustotal.com/api/v3/urls/',
    'IP': 'https://www.virustotal.com/api/v3/ip_addresses/'
}
 
output_txt_lines = []
output_csv_data = []
 
# === Yardımcı Fonksiyonlar === #
def encode_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")
 
def is_valid(value, selected_type):
    patterns = {
        "IP": r"^\d{1,3}(\.\d{1,3}){3}$",
        "Domain": r"^(?!https?://)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
        "URL": r"^https?://",
        "MD5": r"^[a-fA-F0-9]{32}$",
        "SHA-1": r"^[a-fA-F0-9]{40}$",
        "SHA-256": r"^[a-fA-F0-9]{64}$"
    }
    return re.match(patterns[selected_type], value) is not None
 
# === Ana Sorgulama Fonksiyonu === #
def query_items(items, source="manuel"):
    global output_txt_lines, output_csv_data
    output_txt_lines = []
    output_csv_data = []
 
    selected_type = selected_option.get()
    result_text.configure(state="normal")
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, f"{source.capitalize()} giriş yükleniyor...\n")
    app.update()
 
    for value in items:
        value = value.strip()
        if not value or not is_valid(value, selected_type):
            continue
 
        url = VT_URLS[selected_type]
        if selected_type == "URL":
            url += encode_url(value)
        else:
            url += value
 
        headers = {"x-apikey": API_KEY}
 
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                score = data['data']['attributes']['last_analysis_stats']['malicious']
                extra = ""
 
                if selected_type == "IP":
                    extra = data['data']['attributes'].get('as_owner', 'Unknown')
                    line = f"IP: {value} -> Malicious: {score}, ISP: {extra}"
                else:
                    line = f"{selected_type}: {value} -> Malicious: {score}"
 
                output_txt_lines.append(line)
                output_csv_data.append([selected_type, value, score, extra])
 
                if score == 0:
                    color = "green"
                elif score > 0:
                    color = "red"
                else:
                    color = "gray"
 
                result_text.insert(tk.END, line + "\n", color)
            else:
                error_line = f"{value}: API Error (Status {response.status_code})"
                output_txt_lines.append(error_line)
                result_text.insert(tk.END, error_line + "\n", "gray")
        except Exception as e:
            error_line = f"{value}: Error -> {str(e)}"
            output_txt_lines.append(error_line)
            result_text.insert(tk.END, error_line + "\n", "gray")
 
    if not output_txt_lines:
        result_text.insert(tk.END, "Geçerli veri bulunamadı.", "gray")
    result_text.configure(state="disabled")
 
# === Girdi & Kayıt Fonksiyonları === #
def process_file_by_type():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if not file_path:
        return
    with open(file_path, "r", encoding="utf-8") as file:
        lines = file.readlines()
    query_items(lines, source="dosya")
 
def process_manual_input():
    lines = manual_text.get("1.0", tk.END).strip().splitlines()
    query_items(lines, source="manuel")
 
def save_as_txt():
    if not output_txt_lines:
        messagebox.showwarning("Uyarı", "Kaydedilecek veri yok.")
        return
    path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text File", "*.txt")])
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(output_txt_lines))
        messagebox.showinfo("Başarılı", "TXT dosyası kaydedildi.")
 
def save_as_csv():
    if not output_csv_data:
        messagebox.showwarning("Uyarı", "Kaydedilecek veri yok.")
        return
    path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV File", "*.csv")])
    if path:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Tür", "Değer", "Risk Değeri", "Ek Bilgi"])
            writer.writerows(output_csv_data)
        messagebox.showinfo("Başarılı", "CSV dosyası kaydedildi.")
 
def save_as_xlsx():
    if not output_csv_data:
        messagebox.showwarning("Uyarı", "Kaydedilecek veri yok.")
        return
    path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel File", "*.xlsx")])
    if path:
        wb = Workbook()
        ws = wb.active
        ws.title = "VirusTotal Sonuçları"
        ws.append(["Tür", "Değer", "Risk Değeri", "Ek Bilgi"])
        for row in output_csv_data:
            ws.append(row)
        wb.save(path)
        messagebox.showinfo("Başarılı", "XLSX dosyası kaydedildi.")
 
# === GUI Başlangıcı === #
app = tk.Tk()
app.title("VirusTotal Sorgulayıcı - Dosya & Manuel Giriş")
app.geometry("730x740")
app.configure(bg="#f2f2f2")
 
selected_option = tk.StringVar(value="IP")
options = ["IP", "Domain", "URL", "SHA-1", "SHA-256", "MD5"]
 
option_frame = tk.LabelFrame(app, text="Sorgu Türü Seç", padx=10, pady=5, bg="#f2f2f2", font=("Segoe UI", 10, "bold"))
option_frame.pack(pady=10)
 
for opt in options:
    tk.Radiobutton(option_frame, text=opt, variable=selected_option, value=opt, bg="#f2f2f2", font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=8)
 
tk.Button(app, text="📂 Dosya Yükle ve Sorgula", command=process_file_by_type, bg="#ffb347", fg="black", font=("Segoe UI", 10, "bold"), width=40).pack(pady=10)
 
tk.Label(app, text="Manuel Giriş (bir satıra bir değer yaz):", bg="#f2f2f2", font=("Segoe UI", 10)).pack(pady=5)
manual_text = tk.Text(app, height=5, width=80, font=("Consolas", 10))
manual_text.pack(pady=5)
 
tk.Button(app, text="🖊️ Manuel Girişten Sorgula", command=process_manual_input, bg="#add8e6", font=("Segoe UI", 10, "bold"), width=40).pack(pady=10)
 
button_frame = tk.Frame(app, bg="#f2f2f2")
button_frame.pack(pady=5)
 
tk.Button(button_frame, text="💾 TXT olarak kaydet", command=save_as_txt, bg="#e0e0e0", width=22, font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="💾 CSV olarak kaydet", command=save_as_csv, bg="#90ee90", width=22, font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="💾 XLSX olarak kaydet", command=save_as_xlsx, bg="#d0bdf4", width=22, font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=5)
 
result_text = tk.Text(app, height=20, width=80, bg="#ffffe0", font=("Consolas", 10))
result_text.tag_config("green", foreground="green")
result_text.tag_config("red", foreground="red")
result_text.tag_config("gray", foreground="gray")
result_text.pack(pady=10)
 
tk.Label(app, text="Yapımcılar: Mehmet Doğan / Gururcan Kocabıyık / Selim Talha Aksoy", fg="blue", bg="#f2f2f2", font=("Segoe UI", 9)).pack(side=tk.BOTTOM, pady=5)
 
app.mainloop()
