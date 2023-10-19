import socket
import requests
import pyfiglet

VIRUSTOTAL_API_URL = "https://www.virustotal.com/vtapi/v2/file/scan"
VIRUSTOTAL_API_KEY = "YOUR_API_KEY"

def scan_port(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            print(f"Port {port} is open")
        sock.close()
    except socket.error as e:
        print(f"Error occurred while scanning port {port}: {str(e)}")

def vulnerability_scan(target_ip, start_port, end_port):
    print(f"Scanning {target_ip} for open ports...")
    for port in range(start_port, end_port + 1):
        scan_port(target_ip, port)

def scan_file(file_path, api_key):
    try:
        with open(file_path, "rb") as file:
            files = {"file": file}
            params = {"apikey": api_key}
            response = requests.post(VIRUSTOTAL_API_URL, files=files, params=params)
            
            if response.status_code == 200:
                json_response = response.json()
                response_code = json_response.get("response_code")
                if response_code == 1:
                    print(f"File {file_path} is clean")
                elif response_code == -2:
                    print("File is being analyzed, please check back later")
                else:
                    print(f"Potential malware detected: {file_path}")
            else:
                print("Error occurred while scanning the file")
    except requests.RequestException as e:
        print(f"Error occurred while scanning the file: {str(e)}")

# Display tool banner
def display_banner():
    banner_text = pyfiglet.figlet_format("JusNervy")
    print(banner_text)

# Main program loop
def main():
    display_banner()
    print("Welcome to the Cybersecurity Multitool!")

    while True:
        print("Please select an option:")
        print("1. Vulnerability Scanner")
        print("2. Malware Detection")
        print("3. Exit")
        choice = input("Enter your choice (1-3): ")

        if choice == "1":
            target_ip = input("Enter the target IP address: ")
            start_port = int(input("Enter the starting port: "))
            end_port = int(input("Enter the ending port: "))
            if start_port > end_port:
                print("Invalid port range. Please try again.")
                continue
            vulnerability_scan(target_ip, start_port, end_port)
        elif choice == "2":
            file_path = input("Enter the file path to scan: ")
            scan_file(file_path, VIRUSTOTAL_API_KEY)
        elif choice == "3":
            print("Exiting the Cybersecurity Multitool...")
            break
        else:
            print("Invalid choice. Please try again.")

    print("Thank you for using the Cybersecurity Multitool!")

if __name__ == "__main__":
    main()
