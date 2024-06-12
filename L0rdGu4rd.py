import ssl
import socket
import OpenSSL
import argparse
import datetime
import random
import string

def generate_random_user_agent(short=False):
    # Generate a random User-Agent string
    letters = string.ascii_letters
    if short:
        return ''.join(random.choice(letters) for i in range(5))
    else:
        return ''.join(random.choice(letters) for i in range(10))

def scan_ssl(url, args):
    try:
        # Establish a connection to the site
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=url)
        conn.settimeout(10)  # Set timeout for connection
        conn.connect((url, 443))

        # Get certificate
        cert_bin = conn.getpeercert(True)
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)

        # Extract information
        subject = dict(x509.get_subject().get_components())
        issuer = dict(x509.get_issuer().get_components())
        valid_from = datetime.datetime.strptime(x509.get_notBefore().decode('utf-8'), "%Y%m%d%H%M%SZ")
        valid_to = datetime.datetime.strptime(x509.get_notAfter().decode('utf-8'), "%Y%m%d%H%M%SZ")
        cert_algo = x509.get_signature_algorithm().decode('utf-8')

        # Print certificate information
        print("Certificate Information:")
        print("Subject:", subject)
        print("Issuer:", issuer)
        print("Valid From:", valid_from.strftime('%Y-%m-%d %H:%M:%S'))
        print("Valid To:", valid_to.strftime('%Y-%m-%d %H:%M:%S'))
        print("Certificate Algorithm:", cert_algo)

        # Check SSL/TLS version
        ssl_version = conn.version()
        print("\nSSL/TLS Version:", ssl_version)

        # Check for vulnerable protocols
        if ssl_version.startswith("TLS 1.0") or ssl_version.startswith("SSL"):
            print("Warning: Vulnerable protocol version detected.")

        # Check for known vulnerabilities
        if args.all:
            check_all_vulnerabilities(conn, args.user_agent)
        else:
            if args.poodle:
                check_poodle(conn, args.user_agent)
            if args.heartbleed:
                check_heartbleed(conn, args.user_agent)
            if args.beast:
                check_beast(conn, args.user_agent)
            if args.crime:
                check_crime(conn, args.user_agent)
            if args.freak:
                check_freak(conn, args.user_agent)

    except socket.timeout:
        print("Error: Connection timed out. Please check the site and try again.")
    except ssl.SSLError as e:
        print("SSL Error:", e)
    except OpenSSL.crypto.Error as e:
        print("Crypto Error:", e)
    except Exception as e:
        print("Error:", str(e))

def check_all_vulnerabilities(conn, user_agent):
    # Check all vulnerabilities
    print("\nScanning all vulnerabilities...")
    check_poodle(conn, user_agent)
    check_heartbleed(conn, user_agent)
    check_beast(conn, user_agent)
    check_crime(conn, user_agent)
    check_freak(conn, user_agent)

def check_poodle(conn, user_agent):
    # Check for POODLE vulnerability
    try:
        conn.send(f"GET / HTTP/1.1\r\nHost: vulnerable\r\nUser-Agent: {user_agent}\r\nConnection: close\r\n\r\n".encode())
        response = conn.recv(1024)
        if b"ssl 3" in response.lower():
            print("Warning: POODLE vulnerability detected (SSLv3)")
    except Exception as e:
        print(f"Error checking POODLE: {e}")

def check_heartbleed(conn, user_agent):
    # Check for Heartbleed vulnerability
    try:
        conn.send(f"GET / HTTP/1.1\r\nHost: vulnerable\r\nUser-Agent: {user_agent}\r\nConnection: close\r\n\r\n".encode())
        response = conn.recv(1024)
        if b"heartbeat" in response:
            print("Warning: Heartbleed vulnerability detected")
    except Exception as e:
        print(f"Error checking Heartbleed: {e}")

def check_beast(conn, user_agent):
    # Check for BEAST vulnerability
    try:
        conn.send(f"GET / HTTP/1.1\r\nHost: vulnerable\r\nUser-Agent: {user_agent}\r\nConnection: close\r\n\r\n".encode())
        response = conn.recv(1024)
        if b"Set-Cookie" in response:
            print("Warning: BEAST vulnerability detected")
    except Exception as e:
        print(f"Error checking BEAST: {e}")

def check_crime(conn, user_agent):
    # Check for CRIME vulnerability
    try:
        conn.send(f"GET / HTTP/1.1\r\nHost: vulnerable\r\nUser-Agent: {user_agent}\r\nAccept-Encoding: gzip,deflate\r\nConnection: close\r\n\r\n".encode())
        response = conn.recv(1024)
        if b"Content-Encoding: gzip" in response:
            print("Warning: CRIME vulnerability detected")
    except Exception as e:
        print(f"Error checking CRIME: {e}")

def check_freak(conn, user_agent):
    # Check for FREAK vulnerability
    try:
        conn.send(f"GET / HTTP/1.1\r\nHost: vulnerable\r\nUser-Agent: {user_agent}\r\nConnection: close\r\n\r\n".encode())
        response = conn.recv(1024)
        if b"Exported" in response:
            print("Warning: FREAK vulnerability detected")
    except Exception as e:
        print(f"Error checking FREAK: {e}")

def main():
    parser = argparse.ArgumentParser(description='SSL Vulnerability Scanner', formatter_class=argparse.RawDescriptionHelpFormatter, epilog='''
Available options:
  -u URL, --url URL     The URL of the site to scan (e.g., https://example.com)
  -a, --all             Scan for all vulnerabilities
  -p, --poodle          Check for POODLE vulnerability
  -hb, --heartbleed     Check for Heartbleed vulnerability
  -b, --beast           Check for BEAST vulnerability
  -c, --crime           Check for CRIME vulnerability
  -f, --freak           Check for FREAK vulnerability
  -s, --short-user-agent
                        Use a shorter random User-Agent
    ''')

    parser.add_argument('--url', '-u', metavar='url', type=str, required=True, help='The URL of the site to scan (e.g., https://example.com)')
    parser.add_argument('--all', '-a', action='store_true', help='Scan for all vulnerabilities')
    parser.add_argument('--poodle', '-p', action='store_true', help='Check for POODLE vulnerability')
    parser.add_argument('--heartbleed', '-hb', action='store_true', help='Check for Heartbleed vulnerability')
    parser.add_argument('--beast', '-b', action='store_true', help='Check for BEAST vulnerability')
    parser.add_argument('--crime', '-c', action='store_true', help='Check for CRIME vulnerability')
    parser.add_argument('--freak', '-f', action='store_true', help='Check for FREAK vulnerability')
    parser.add_argument('--short-user-agent', '-s', action='store_true', help='Use a shorter random User-Agent')

    args = parser.parse_args()

    # Generate random User-Agent
    if args.short_user_agent:
        args.user_agent = generate_random_user_agent(short=True)
    else:
        args.user_agent = generate_random_user_agent()

    print(f"Using User-Agent: {args.user_agent}")

    scan_ssl(args.url, args)

if __name__ == "__main__":
    main()
