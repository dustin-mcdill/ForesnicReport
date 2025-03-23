import psutil
import socket
import platform
import datetime
import getpass

class ForensicReport:

    def __init__(self):
        self.report_lines = []

    def log(self, label, value):
        line = f"{label}: {value}"
        print(line)
        self.report_lines.append(line)

    def generate(self):
        self.log("====== FORENSIC REPORT ======", "")
        self.log("Report Generated On", datetime.datetime.now().isoformat())
        self.log("Current User", getpass.getuser())
        self.log("Hostname", socket.gethostname())
        self.log("OS", f"{platform.system()} {platform.release()} {platform.version()}")
        self.log("Architecture", platform.architecture()[0])
        self.log("Processor", platform.processor())

        self.log("\n====== ACTIVE CONNECTIONS ======", "")
        for conn in psutil.net_connections(kind='inet'):
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            status = conn.status
            self.log("Connection", f"{laddr} --> {raddr} | Status: {status}")

        self.log("\n====== SUSPICIOUS PROCESSES ======", "")
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'status']):
            try:
                if proc.info['username'] not in ['SYSTEM', 'Administrator', getpass.getuser()]:
                    self.log("⚠️ Anomaly", f"PID {proc.info['pid']} ({proc.info['name']}) - User: {proc.info['username']}")
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

        self.log("\n====== STARTUP PROCESS ======", "")
        self.log("\n====== PROCESSING REPORT ======", "")

    def write_report(self, filepath='anomaly_report.txt'):
        with open(filepath, 'w', encoding='utf-8') as f:

            for line in self.report_lines:
                f.write(line + '\n')


if __name__ == "__main__":
    report = ForensicReport()
    report.generate()
    report.write_report()
