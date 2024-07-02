import tkinter as tk
from tkinter import ttk, messagebox
import os


def list_files():
    return [
        "local_vulnerability_checker(GUI).py",
        "network_module(GUI).py",
        "online_vulnerability_checker(GUI).py",
        "packet_sniffer(GUI).py",
        "password_module(GUI).py"
    ]


def run_file(filename):
    try:
        with open(filename) as file:
            exec(file.read(), globals())
    except Exception as e:
        messagebox.showerror("Error", f"Error running file: {e}")


def on_select(event):
    selected_file = files_listbox.get(files_listbox.curselection())
    run_file(selected_file)


def main():
    global files_listbox
    files = list_files()

    root = tk.Tk()
    root.title("Python File Runner")

    # Set window size
    root.geometry("800x600")

    ttk.Label(root, text="Select a Python file to run:", font=("Helvetica", 16)).pack(pady=20)

    files_listbox = tk.Listbox(root, height=len(files), font=("Helvetica", 14))
    for file in files:
        files_listbox.insert(tk.END, file)
    files_listbox.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)

    files_listbox.bind('<<ListboxSelect>>', on_select)

    root.mainloop()


if __name__ == "__main__":
    main()
