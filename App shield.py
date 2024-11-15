import os
import yaml
from tkinter import Tk, Label, Button, StringVar, filedialog, messagebox, Entry, Frame, Listbox, Scrollbar
from androguard.misc import AnalyzeAPK  # Ensure this import is present

# Function to load vulnerability rules from the YAML file
def load_vulnerability_rules(file_path):
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)

# Function to scan APK for vulnerabilities
def scan_apk(apk_path, rules_path):
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")
    
    print(f"Analyzing APK: {apk_path}")
    a, d, dx = AnalyzeAPK(apk_path)

    if not os.path.exists(rules_path):
        raise FileNotFoundError(f"Rules file not found: {rules_path}")

    rules = load_vulnerability_rules(rules_path)
    print(f"Loaded {len(rules)} vulnerability rules.")

    vulnerabilities_found = []
    for rule in rules:
        for method in dx.get_methods():
            if rule['method_name'] in method.name:
                vulnerabilities_found.append({
                    'issue': rule['issue'],
                    'method': method.name,
                    'description': rule['description']
                })

    return vulnerabilities_found

# Function to display a list of vulnerabilities
def display_vulnerabilities(vulnerabilities):
    vulnerabilities_listbox.delete(0, 'end')  # Clear the listbox
    if vulnerabilities:
        for index, vuln in enumerate(vulnerabilities):
            vulnerabilities_listbox.insert(index, f"{vuln['issue']} - {vuln['method']}")
    else:
        vulnerabilities_listbox.insert(0, "No vulnerabilities found.")

# Function to show details of the selected vulnerability
def show_vulnerability_report():
    selected_index = vulnerabilities_listbox.curselection()
    if selected_index:
        selected_vuln = vulnerabilities[selected_index[0]]
        vuln_report = f"Issue: {selected_vuln['issue']}\nMethod: {selected_vuln['method']}\nDescription: {selected_vuln['description']}"
        result_label.set(vuln_report)
    else:
        messagebox.showwarning("Warning", "Please select a vulnerability to view the report.")

# Function to handle the APK file selection
def select_apk_file():
    apk_path = filedialog.askopenfilename(title="Select APK file", filetypes=[("APK files", "*.apk")])
    if apk_path:
        apk_entry_widget.delete(0, 'end')
        apk_entry_widget.insert(0, apk_path)

# Function to start the vulnerability scan
def start_scan():
    apk_path = apk_entry_widget.get()
    rules_path = "C:/Users/ADMN/Documents/AppShield/rules.yaml"
    try:
        global vulnerabilities
        vulnerabilities = scan_apk(apk_path, rules_path)
        display_vulnerabilities(vulnerabilities)
    except FileNotFoundError as e:
        messagebox.showerror("Error", str(e))
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Function to clear the results
def clear_results():
    vulnerabilities_listbox.delete(0, 'end')
    result_label.set("Results cleared.")

# Set up the main application window
root = Tk()
root.title("App Shield")
root.geometry("600x600")

frame = Frame(root, padx=20, pady=20)
frame.pack(fill='both', expand=True)

# APK selection section
apk_label = Label(frame, text="Select APK file:", font=("Arial", 12))
apk_label.pack(pady=10)

apk_entry_widget = Entry(frame, width=50, font=("Arial", 12))
apk_entry_widget.pack(pady=5)

browse_button = Button(frame, text="Browse", command=select_apk_file, font=("Arial", 12), bg="#007BFF", fg="white")
browse_button.pack(pady=10)

# Vulnerability list section
vuln_list_label = Label(frame, text="Available Vulnerabilities:", font=("Arial", 12))
vuln_list_label.pack(pady=10)

# Listbox to display vulnerabilities
vulnerabilities_listbox = Listbox(frame, height=10, width=50, font=("Arial", 12))
vulnerabilities_listbox.pack(pady=5)

# Scrollbar for the Listbox
scrollbar = Scrollbar(frame)
scrollbar.pack(side='right', fill='y')
vulnerabilities_listbox.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=vulnerabilities_listbox.yview)

# Result display section
result_label = StringVar()
result_display = Label(frame, textvariable=result_label, justify='left', font=("Arial", 12), bg="#F8F9FA", wraplength=500)
result_display.pack(pady=10)

# Buttons to control the scan and view
scan_button = Button(frame, text="Start Scan", command=start_scan, font=("Arial", 12), bg="#28A745", fg="white")
scan_button.pack(pady=5)

report_button = Button(frame, text="View Report", command=show_vulnerability_report, font=("Arial", 12), bg="#17A2B8", fg="white")
report_button.pack(pady=5)

clear_button = Button(frame, text="Clear Results", command=clear_results, font=("Arial", 12), bg="#DC3545", fg="white")
clear_button.pack(pady=5)

# Run the application
root.mainloop()


# 100 lines of harmless code
def do_nothing_1():
    pass

def do_nothing_2():
    pass

def do_nothing_3():
    pass

def do_nothing_4():
    pass

def do_nothing_5():
    pass

def do_nothing_6():
    pass

def do_nothing_7():
    pass

def do_nothing_8():
    pass

def do_nothing_9():
    pass

def do_nothing_10():
    pass

def do_nothing_11():
    pass

def do_nothing_12():
    pass

def do_nothing_13():
    pass

def do_nothing_14():
    pass

def do_nothing_15():
    pass

def do_nothing_16():
    pass

def do_nothing_17():
    pass

def do_nothing_18():
    pass

def do_nothing_19():
    pass

def do_nothing_20():
    pass

def do_nothing_21():
    pass

def do_nothing_22():
    pass

def do_nothing_23():
    pass

def do_nothing_24():
    pass

def do_nothing_25():
    pass

def do_nothing_26():
    pass

def do_nothing_27():
    pass

def do_nothing_28():
    pass

def do_nothing_29():
    pass

def do_nothing_30():
    pass

def do_nothing_31():
    pass

def do_nothing_32():
    pass

def do_nothing_33():
    pass

def do_nothing_34():
    pass

def do_nothing_35():
    pass

def do_nothing_36():
    pass

def do_nothing_37():
    pass

def do_nothing_38():
    pass

def do_nothing_39():
    pass

def do_nothing_40():
    pass

def do_nothing_41():
    pass

def do_nothing_42():
    pass

def do_nothing_43():
    pass

def do_nothing_44():
    pass

def do_nothing_45():
    pass

def do_nothing_46():
    pass

def do_nothing_47():
    pass

def do_nothing_48():
    pass

def do_nothing_49():
    pass

def do_nothing_50():
    pass

def do_nothing_51():
    pass

def do_nothing_52():
    pass

def do_nothing_53():
    pass

def do_nothing_54():
    pass

def do_nothing_55():
    pass

def do_nothing_56():
    pass

def do_nothing_57():
    pass

def do_nothing_58():
    pass

def do_nothing_59():
    pass

def do_nothing_60():
    pass

def do_nothing_61():
    pass

def do_nothing_62():
    pass

def do_nothing_63():
    pass

def do_nothing_64():
    pass

def do_nothing_65():
    pass

def do_nothing_66():
    pass

def do_nothing_67():
    pass

def do_nothing_68():
    pass

def do_nothing_69():
    pass

def do_nothing_70():
    pass

def do_nothing_71():
    pass

def do_nothing_72():
    pass

def do_nothing_73():
    pass

def do_nothing_74():
    pass

def do_nothing_75():
    pass

def do_nothing_76():
    pass

def do_nothing_77():
    pass

def do_nothing_78():
    pass

def do_nothing_79():
    pass

def do_nothing_80():
    pass

def do_nothing_81():
    pass

def do_nothing_82():
    pass

def do_nothing_83():
    pass

def do_nothing_84():
    pass

def do_nothing_85():
    pass

def do_nothing_86():
    pass

def do_nothing_87():
    pass

def do_nothing_88():
    pass

def do_nothing_89():
    pass

def do_nothing_90():
    pass

def do_nothing_91():
    pass

def do_nothing_92():
    pass

def do_nothing_93():
    pass

def do_nothing_94():
    pass

def do_nothing_95():
    pass

def do_nothing_96():
    pass

def do_nothing_97():
    pass

def do_nothing_98():
    pass

def do_nothing_99():
    pass

def do_nothing_100():
    pass
