import tkinter as tk
from tkinter import ttk
import socket
import time
import threading
from queue import Queue


class PortScanner(tk.Frame):
    def __init__(self, parent, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)
        self.parent = parent

        topFrame = tk.Frame(window)
        scan_label = tk.Label(topFrame, text="IP ")
        scan_label.pack(side=tk.LEFT)
        ipvar = tk.StringVar()
        ipeb = ttk.Entry(topFrame, width=15, textvariable=ipvar)
        ipeb.pack(side=tk.LEFT)
        ipeb.focus()
        btnStart = tk.Button(topFrame, text="Scan", command=lambda: start_scan())
        btnStart.pack(side=tk.LEFT)
        btnStop = tk.Button(topFrame, text="Stop", command=lambda: stop_scan(), state=tk.DISABLED)
        btnStop.pack(side=tk.LEFT)
        topFrame.pack(side=tk.TOP, pady=(5, 0))

        # Middle frame consisting of two labels for displaying the host and port info
        middleFrame = tk.Frame(window)
        lblHost = tk.Label(middleFrame, text="Target Host: ")
        lblHost.pack(side=tk.LEFT)
        lbltime = tk.Label(middleFrame, text="Time Taken: ")
        lbltime.pack(side=tk.LEFT)
        middleFrame.pack(side=tk.TOP, pady=(5, 0))


        clientFrame = tk.Frame(window)
        lblLine = tk.Label(clientFrame, text="**********Scan Result**********").pack()
        scrollBar = tk.Scrollbar(clientFrame)
        scrollBar.pack(side=tk.RIGHT, fill=tk.Y)
        tkDisplay = tk.Text(clientFrame, height=15, width=30)
        tkDisplay.pack(side=tk.LEFT, fill=tk.Y, padx=(5, 0))
        scrollBar.config(command=tkDisplay.yview)
        tkDisplay.config(yscrollcommand=scrollBar.set, background="#F4F6F7", highlightbackground="grey",
                         state="disabled")
        clientFrame.pack(side=tk.BOTTOM, pady=(5, 10))

        tkDisplay.config(state=tk.NORMAL)
        tkDisplay.delete('1.0', tk.END)
        tkDisplay.config(state=tk.DISABLED)

        # Start server function
        rport = []

        def start_scan():
            btnStart.config(state=tk.DISABLED)
            btnStop.config(state=tk.NORMAL)
            tkDisplay.config(state=tk.NORMAL)
            socket.setdefaulttimeout(0.25)
            print_lock = threading.Lock()
            target = ipvar.get()
            t_IP = socket.gethostbyname(target)
            lblHost["text"] = "Target Host: " + t_IP

            def portscan(port):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    con = s.connect_ex((t_IP, port))
                    with print_lock:
                        rport.append(port)

                    con.close()
                except:
                    pass

            def threader():
                while True:
                    worker = q.get()
                    portscan(worker)
                    q.task_done()

            q = Queue()
            starttime = time.time()
            for x in range(100):
                t = threading.Thread(target=threader)
                t.daemon = True
                t.start()
            for worker in range(1, 500):
                q.put(worker)

            q.join()
            t_time = time.time() - starttime
            lbltime["text"] = "Time Taken: " + str(t_time)
            for rp in rport:
                tkDisplay.insert(tk.END, str(rp) + " Port is open \n")
            tkDisplay.config(state=tk.DISABLED)

        def stop_scan():
            btnStart.config(state=tk.NORMAL)
            btnStop.config(state=tk.DISABLED)
            tkDisplay.config(state=tk.DISABLED)


if __name__ == "__main__":
    window = tk.Tk()
    window.title("Port Scanner")
    window.configure(background='#153b3b')
    window.resizable(width=0, height=0)
    my_gui = PortScanner(window)
    window.mainloop()
