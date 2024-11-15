import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import Text, Scrollbar, VERTICAL, RIGHT, Y, END
import backend  # Import the backend script

# Function to display open ports in the GUI
def display_open_ports(open_ports):
    result_text.delete(1.0, END)  # Clear the previous result
    result_text.insert(END, f"Open Ports: {open_ports}\n\n")

# Function to display vulnerabilities in the GUI
def display_vulnerability(vulnerability):
    result_text.insert(END, f"Issue: {vulnerability['issue']}\n")
    result_text.insert(END, f"Method: {vulnerability['method']}\n")
    result_text.insert(END, f"Description: {vulnerability['description']}\n\n")

# Function to handle APK file selection
def select_apk_file():
    apk_path = filedialog.askopenfilename(title="Select APK file", filetypes=[("APK files", "*.apk")])
    if apk_path:
        apk_entry_widget.delete(0, 'end')
        apk_entry_widget.insert(0, apk_path)

# Function to start the scan
def start_scan():
    apk_path = apk_entry_widget.get()
    try:
        open_ports = backend.identify_open_ports()
        display_open_ports(open_ports)

        vulnerabilities = backend.scan_apk(apk_path)
        for vuln in vulnerabilities:
            display_vulnerability(vuln)

        download_button.config(state='normal', command=lambda: save_report(vulnerabilities, open_ports))
    except FileNotFoundError as e:
        messagebox.showerror("Error", str(e))
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Function to save the report
def save_report(vulnerabilities, open_ports):
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if file_path:
        backend.save_report(vulnerabilities, open_ports, file_path)
        messagebox.showinfo("Success", "Report saved successfully.")

# Set up the GUI
root = tk.Tk()
root.title("App Shield")
root.geometry("600x600")

frame = tk.Frame(root, padx=20, pady=20)
frame.pack(fill='both', expand=True)

apk_label = tk.Label(frame, text="Select APK file:", font=("Arial", 12))
apk_label.pack(pady=10)

apk_entry_widget = tk.Entry(frame, width=50, font=("Arial", 12))
apk_entry_widget.pack(pady=5)

browse_button_apk = tk.Button(frame, text="Browse APK", command=select_apk_file, font=("Arial", 12), bg="#007BFF", fg="white")
browse_button_apk.pack(pady=10)

scan_button = tk.Button(frame, text="Start Scan", command=start_scan, font=("Arial", 12), bg="#28A745", fg="white")
scan_button.pack(pady=20)

result_text = Text(frame, wrap='word', font=("Arial", 12), height=10)
result_text.pack(pady=10, fill='both', expand=True)

scrollbar = Scrollbar(result_text, orient=VERTICAL)
scrollbar.pack(side=RIGHT, fill=Y)
result_text.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=result_text.yview)

download_button = tk.Button(frame, text="Download Report", state='disabled', font=("Arial", 12), bg="#17A2B8", fg="white")
download_button.pack(pady=10)

root.mainloop()
