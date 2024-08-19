import tkinter as tk
from tkinter import messagebox, Scrollbar, Text, filedialog
import requests
import webbrowser
import nmap
from PIL import Image, ImageTk
import threading
import re


# Function to open location on Google Maps
def open_map(lat, lon):
    url = f"https://www.google.com/maps?q={lat},{lon}"
    webbrowser.open(url)


# Function to validate IP address
def is_valid_ip(ip):
    pattern = re.compile(
        r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    return pattern.match(ip) is not None


# Function to get geolocation data
def get_geolocation():
    ip_address = entry_ip.get()

    if not is_valid_ip(ip_address):
        messagebox.showerror("Error", "Invalid IP address")
        return

    api_key = 'f344f144cadd5b'  # Use the provided API key
    url = f'https://ipinfo.io/{ip_address}/json?token={api_key}'

    try:
        response = requests.get(url)
        response.raise_for_status()  # Ensure we catch HTTP errors
        data = response.json()

        if isinstance(data, dict):  # Check if data is a dictionary
            if 'error' in data:
                messagebox.showerror("Error", data['error'].get('info', 'Unknown error'))
            else:
                location_info = f"""
IP Address: {data.get('ip', 'N/A')}
City: {data.get('city', 'N/A')}
Region: {data.get('region', 'N/A')}
Country: {data.get('country', 'N/A')}
Location: {data.get('loc', 'N/A')}
Timezone: {data.get('timezone', 'N/A')}
"""

                # Save to history
                history_text.insert(tk.END, location_info + "\n" + "-" * 40 + "\n")

                # Show custom information popup
                show_custom_info_popup(location_info)

                # Open map
                loc = data.get('loc', '0,0').split(',')
                if len(loc) == 2:
                    open_map(loc[0], loc[1])
        else:
            messagebox.showerror("Error", "Unexpected response format.")
    except requests.exceptions.RequestException as e:
        messagebox.showerror("Error", f"Request failed: {str(e)}")
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")


# Function to show custom information popup
def show_custom_info_popup(info):
    popup = tk.Toplevel(root)
    popup.title("Geolocation Info")
    popup.configure(bg='black')
    popup.iconbitmap('skull.ico')

    info_label = tk.Label(popup, text=info, font=("Courier", 12), fg='green', bg='black', justify=tk.LEFT)
    info_label.pack(pady=10, padx=10)

    ok_button = tk.Button(popup, text="OK", command=popup.destroy, font=("Courier", 12), fg='black', bg='green')
    ok_button.pack(pady=10)


# Function to start the geolocation fetch in a separate thread
def start_geolocation_fetch():
    threading.Thread(target=get_geolocation).start()


# Function to scan the IP using Nmap
def scan_ip():
    ip_address = entry_ip.get()

    if not is_valid_ip(ip_address):
        messagebox.showerror("Error", "Invalid IP address")
        return

    scanner = nmap.PortScanner()

    try:
        scan_result = scanner.scan(ip_address, arguments='-O -sV')
        scan_info = f"IP Address: {ip_address}\n\n"

        if ip_address in scan_result['scan']:
            scan_data = scan_result['scan'][ip_address]

            # Parsing OS information from osmatch
            if 'osmatch' in scan_data:
                scan_info += "Operating System:\n"
                for osmatch in scan_data['osmatch']:
                    scan_info += f"  - {osmatch['name']} (accuracy: {osmatch['accuracy']}%)\n"
                    for osclass in osmatch['osclass']:
                        scan_info += f"    - {osclass['osfamily']} {osclass.get('osgen', 'N/A')}\n"

            # Parsing TCP port information
            if 'tcp' in scan_data:
                scan_info += "\nOpen Ports:\n"
                for port in scan_data['tcp']:
                    port_info = scan_data['tcp'][port]
                    state = port_info['state']
                    name = port_info['name']
                    product = port_info.get('product', 'N/A')
                    version = port_info.get('version', 'N/A')
                    extrainfo = port_info.get('extrainfo', 'N/A')
                    scan_info += f"  Port {port}: {name} ({state})\n"
                    scan_info += f"    Product: {product}\n"
                    scan_info += f"    Version: {version}\n"
                    scan_info += f"    Extra Info: {extrainfo}\n"
        else:
            scan_info += "No scan results available.\n"

        # Save to history
        history_text.insert(tk.END, scan_info + "\n" + "-" * 40 + "\n")

        # Show scan information in a custom popup
        show_custom_info_popup(scan_info)

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during the scan: {str(e)}")
        history_text.insert(tk.END, f"An error occurred during the scan: {str(e)}\n" + "-" * 40 + "\n")


# Function to start the IP scan in a separate thread
def start_ip_scan():
    threading.Thread(target=scan_ip).start()


# Function to save history to a file
def save_history():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        with open(file_path, 'w') as file:
            file.write(history_text.get(1.0, tk.END))


# Function to clear the history
def clear_history():
    history_text.delete(1.0, tk.END)


# Function to toggle dark/light mode
def toggle_mode():
    global dark_mode
    if dark_mode:
        root.configure(bg='white')
        history_text.configure(bg='white', fg='black')
        dark_mode = False
    else:
        root.configure(bg='black')
        history_text.configure(bg='black', fg='green')
        dark_mode = True


# Function to show the main application
def show_main_application():
    splash.destroy()

    # Set up the main GUI with a hacking theme
    global root, dark_mode
    root = tk.Tk()
    root.title("IP Geolocation Finder")
    root.configure(bg='black')
    root.iconbitmap('skull.ico')  # Set your icon path

    dark_mode = True  # Start in dark mode

    # Title Label
    tk.Label(root, text="IP Geolocation Finder", font=("Courier", 16), fg='green', bg='black').pack(pady=10)

    # Input Field
    tk.Label(root, text="Enter IP Address:", font=("Courier", 12), fg='green', bg='black').pack(pady=5)
    global entry_ip
    entry_ip = tk.Entry(root, font=("Courier", 12))
    entry_ip.pack(pady=5)

    # Scan Button
    tk.Button(root, text="Scan IP", command=start_ip_scan, font=("Courier", 12), fg='black', bg='green').pack(pady=10)

    # Fetch Button
    tk.Button(root, text="Get Location", command=start_geolocation_fetch, font=("Courier", 12), fg='black',
              bg='green').pack(pady=10)

    # Save History Button
    tk.Button(root, text="Save History", command=save_history, font=("Courier", 12), fg='black', bg='green').pack(
        pady=10)

    # Clear History Button
    tk.Button(root, text="Clear History", command=clear_history, font=("Courier", 12), fg='black', bg='green').pack(
        pady=10)

    # Toggle Mode Button
    tk.Button(root, text="Toggle Dark/Light Mode", command=toggle_mode, font=("Courier", 12), fg='black',
              bg='green').pack(pady=10)

    # History Section
    tk.Label(root, text="History:", font=("Courier", 12), fg='green', bg='black').pack(pady=5)
    history_frame = tk.Frame(root, bg='black')
    history_frame.pack(pady=5)
    history_scroll = Scrollbar(history_frame)
    history_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    global history_text
    history_text = Text(history_frame, width=60, height=10, font=("Courier", 10), bg='black', fg='green',
                        yscrollcommand=history_scroll.set)
    history_text.pack(side=tk.LEFT, fill=tk.BOTH)
    history_scroll.config(command=history_text.yview)

    root.mainloop()


# Set up the splash screen
root = tk.Tk()
root.withdraw()  # Hide the main window

splash = tk.Toplevel(root)
splash.title("Splash Screen")
splash.configure(bg='black')
splash.iconbitmap('skull.ico')  # Set your icon path

# Load splash image
splash_image_path = "hacker.png"  # Specify the path to your splash image
splash_image = Image.open(splash_image_path)
splash_photo = ImageTk.PhotoImage(splash_image)

splash_label = tk.Label(splash, image=splash_photo, bg='black')
splash_label.pack()

# Set a timer to destroy the splash screen and open the main application
root.after(2000, show_main_application)  # 2000 milliseconds = 2 seconds

root.mainloop()