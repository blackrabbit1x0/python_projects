import shodan
import tkinter as tk
from tkinter import scrolledtext, Button, messagebox, Frame
import threading
import webbrowser

# Your Shodan API key
API_KEY = '9mGpjfEh9zLZ0slMt0iXfYW8XZHMsciA'
api = shodan.Shodan(API_KEY)

class CCTVScraperApp:
    def __init__(self, root):
        self.root = root
        self.setup_gui()
        self.running = False
        self.thread = None

    def setup_gui(self):
        self.root.title("Advanced CCTV Scraper")
        self.root.geometry("600x450")
        self.root.configure(bg='#121212')  # Dark background color

        # Styling for the text widget
        text_style = {
            'bg': '#121212',  # Background color for text field
            'fg': '#00FF00',  # Neon green text color
            'insertbackground': 'white',  # Cursor color
            'font': ('Consolas', 12)  # Consistent with professional coding environments
        }

        self.output_text = scrolledtext.ScrolledText(self.root, height=15, **text_style)
        self.output_text.pack(pady=20)
        self.output_text.bind("<Double-1>", self.open_in_browser)  # Bind double click to open in browser

        # Frame for buttons, with the same background color
        button_frame = Frame(self.root, bg='#121212')
        button_frame.pack(pady=20)

        self.start_button = Button(button_frame, text="Start Scanning", command=self.start_scraping, fg='white', bg='#15c213', font=('Consolas', 10, 'bold'))
        self.start_button.pack(side=tk.LEFT, padx=10)

        self.stop_button = Button(button_frame, text="Stop Scanning", command=self.stop_scraping, fg='white', bg='#ff6347', font=('Consolas', 10, 'bold'))
        self.stop_button.pack(side=tk.LEFT, padx=10)

        self.clear_button = Button(button_frame, text="Clear", command=self.clear_output, fg='white', bg='#555555', font=('Consolas', 10, 'bold'))
        self.clear_button.pack(side=tk.RIGHT, padx=10)

    def find_cameras(self):
        try:
            results = api.search('webcamXP')
            self.output_text.delete('1.0', tk.END)  # Clear previous results
            for result in results['matches']:
                ip_link = f"http://{result['ip_str']}:{result['port']}"
                self.output_text.insert(tk.END, f"{ip_link}\n")
                if not self.running:
                    break
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
        finally:
            self.running = False
            self.start_button.config(state=tk.NORMAL)

    def start_scraping(self):
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self.find_cameras)
            self.thread.start()
            self.start_button.config(state=tk.DISABLED)

    def stop_scraping(self):
        self.running = False
        self.start_button.config(state=tk.NORMAL)

    def clear_output(self):
        self.output_text.delete('1.0', tk.END)  # Clear the text area

    def open_in_browser(self, event):
        try:
            position = self.output_text.index("@%d,%d" % (event.x, event.y))
            linestart = position.split('.')[0] + ".0"
            lineend = position.split('.')[0] + ".end"
            url = self.output_text.get(linestart, lineend).strip()
            if url.startswith("http://") or url.startswith("https://"):
                webbrowser.open(url)
            else:
                messagebox.showerror("Error", "No valid URL found on this line.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while trying to open the URL: {str(e)}")

root = tk.Tk()
app = CCTVScraperApp(root)
root.mainloop()
