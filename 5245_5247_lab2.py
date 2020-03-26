# Don't forget to change this file's name before submission.
import sys
import os
import enum
from socket import *
import socket

cache = {}

class HttpRequestInfo(object):
    """
    Represents a HTTP request information

    Since you'll need to standardize all requests you get
    as specified by the document, after you parse the
    request from the TCP packet put the information you
    get in this object.

    To send the request to the remote server, call to_http_string
    on this object, convert that string to bytes then send it in
    the socket.

    client_address_info: address of the client;
    the client of the proxy, which sent the HTTP request.

    requested_host: the requested website, the remote website
    we want to visit.

    requested_port: port of the webserver we want to visit.

    requested_path: path of the requested resource, without
    including the website name.

    NOTE: you need to implement to_http_string() for this class.
    """

    def __init__(self, client_info, method: str, requested_host: str,requested_port: int, requested_path: str, headers: list):
        self.method = method
        self.client_address_info = client_info
        self.requested_host = requested_host
        self.requested_port = requested_port
        self.requested_path = requested_path
        self.headers = headers

    def to_http_string(self):
        http_binary = self.method + b' ' + self.requested_path + b' HTTP/1.0\r\n'
        for header in self.headers:
            http_binary += header[0] + b': ' + header[1] + b'\r\n'
        http_binary += b'\r\n'
        return http_binary.decode('UTF-8')

    def to_byte_array(self, http_string):
        return bytes(http_string, "UTF-8")

    def display(self):
        print(f"Client:", self.client_address_info)
        print(f"Method:", self.method)
        print(f"Host:", self.requested_host)
        print(f"Path:", self.requested_path)
        print(f"Port:", self.requested_port)
        print("Headers:\n", self.headers)


class HttpErrorResponse(object):
    def __init__(self, code, message):
        self.code = code
        self.message = message

    def to_http_string(self):
        response_binary = b'HTTP/1.0 ' + self.code + b' ' + self.message + b'\r\n'
        return response_binary.decode('UTF-8')

    def to_byte_array(self, http_string):
        return bytes(http_string, "UTF-8")

    def display(self):
        print(self.to_http_string())


class HttpRequestState(enum.Enum):
    INVALID_INPUT = 0
    NOT_SUPPORTED = 1
    GOOD = 2
    PLACEHOLDER = -1


def entry_point(proxy_port_number):
    proxy_as_server = setup_proxy_as_server(proxy_port_number)
    proxy_as_client = setup_proxy_as_client()
    client, address = connect_to_client(proxy_as_server)
    http_raw_data = receive_from_client(client)
    pipelined = http_request_pipeline(address, http_raw_data)
    if is_error_response(pipelined):
        response_string = pipelined.to_http_string()
        client.send(pipelined.to_byte_array(response_string))
    else:
        host_path = (pipelined.requested_host, pipelined.requested_path)
        if host_path in cache:
            client.send(cache[host_path])
            print('Cached version sent')
        else:
            print(pipelined.to_http_string())
            remote_address = get_remote_address(pipelined)
            connect_to_remote(proxy_as_client, remote_address)
            http_string = pipelined.to_http_string()
            send_to_remote(proxy_as_client, pipelined.to_byte_array(http_string), remote_address)
            # print(f'Sended to remote: \n {pipelined.to_byte_array(http_string)}')
            response = receive_from_remote(proxy_as_client)
            print('Receieved from remote')
            # print(f'Response is:\n {response}')
            cache[host_path] = response
            client.send(response)
    proxy_as_client.close()
    client.close()
    # return None // IS it good to put (return None) or just remove it and put return type beside the definition of method or not??????

def setup_proxy_as_client():
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def get_remote_address(pipelined):
    return (socket.gethostbyname(pipelined.requested_host), int(pipelined.requested_port))

def connect_to_remote(proxy, remote_address):
    proxy.connect(remote_address)
    print('Connected to remote')

def send_to_remote(proxy, http_request, remote_address):
    proxy.sendto(http_request, remote_address)
    print('Sent to remote')

def receive_from_remote(proxy):
    BUFF_SIZE = 4096
    data = b''
    while True:
        chunk = proxy.recv(BUFF_SIZE)
        data += chunk
        if len(chunk) < BUFF_SIZE: break
    # return proxy.recvfrom(102400)[0]
    return data

def is_error_response(pipelined):
    return isinstance(pipelined, HttpErrorResponse)

def setup_proxy_as_server(proxy_port_number):
    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip_address = '192.168.1.11'
    address = (ip_address, int(proxy_port_number))
    proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy.bind(address)
    proxy.listen(100)
    return proxy

def connect_to_client(proxy):
    client, address = proxy.accept()
    print(f"Connection from {address} has been established!")
    return client, address

def receive_from_client(client):
    data = b""
    while not data.endswith(b'\r\n\r\n'):
        data += client.recv(1024)
    return data
    # while True:
        # chunk = client.recv(4096)
        # if not chunk: break
        # data += chunk
    # return data

def http_request_pipeline(source_addr, http_raw_data):
    parsed = parse_http_request(source_addr, http_raw_data)
    request_status = check_http_request_validity(parsed)
    if is_valid_request(request_status):
        sanitized = sanitize_http_request(parsed)
        return sanitized
    else:
        return appropriate_response(request_status)

def is_valid_request(request_state):
    return request_state == HttpRequestState.GOOD

def appropriate_response(request_status):
    if request_status == HttpRequestState.INVALID_INPUT:
        return HttpErrorResponse(b'400', b'Bad Request')
    elif request_status == HttpRequestState.NOT_SUPPORTED:
        return HttpErrorResponse(b'501', b'Method Not Implemented')

def parse_http_request(source_addr, http_raw_data) -> HttpRequestInfo:
    http_request = http_raw_data.split(b'\r\n')[:-2]
    method, url = parse_request_line(http_request[0])
    headers = http_request[1:]
    host_header = get_host_header(headers)
    ret = HttpRequestInfo(source_addr, method, host_header, None, url, headers)
    return ret

def parse_request_line(request_line):
    request_line = request_line.split(b' ')
    method = request_line[0]
    url = b''
    for i in range(1, len(request_line)):
        url += request_line[i] + b' '
    return method, url

def get_host_header(headers):
    host_header = None
    for header in headers:
        if header.lower().startswith(b'host'):
            host_header = header
            headers.remove(host_header)
            break
    return host_header

def check_http_request_validity(http_request_info: HttpRequestInfo) -> HttpRequestState:
    not_supported = [b'PUT', b'PATCH', b'DELETE', b'HEAD', b'POST', b'CONNECT', b'OPTIONS', b'TRACE']
    if (not http_request_info.requested_path.startswith(b'http') and not http_request_info.requested_path.startswith(b'/')) \
            or (not http_request_info.requested_path.endswith(b' HTTP/1.0 ') and not http_request_info.requested_path.endswith(b' HTTP/1.1 ')):
        return HttpRequestState.INVALID_INPUT
    elif http_request_info.method != b'GET' and http_request_info.method not in not_supported:
        return HttpRequestState.INVALID_INPUT
    elif http_request_info.requested_host is None and http_request_info.requested_path.startswith(b'/'):
        return HttpRequestState.INVALID_INPUT
    elif http_request_info.requested_host is not None and not is_correct_host_header(http_request_info.requested_host) or not is_correct_form(http_request_info.headers):
        return HttpRequestState.INVALID_INPUT
    elif http_request_info.method in not_supported:
        return HttpRequestState.NOT_SUPPORTED
    elif http_request_info.method == b'GET':
        return HttpRequestState.GOOD

def is_correct_form(headers):
    for header in headers:
        if len(header.split(b': ')) != 2: return False
    return True

def is_correct_host_header(host_header):
    return len(host_header.split(b': ')) > 1

def sanitize_http_request(request_info: HttpRequestInfo) -> HttpRequestInfo:
    path, host = expand_url(request_info.requested_path)
    port = b'80'
    if request_info.requested_host is not None:
        host, port = expand_host(request_info.requested_host.split(b': ')[1])
    # print(host)
    headers = sanitize_headers(request_info.headers, host)
    ret = HttpRequestInfo(request_info.client_address_info, request_info.method, host, port, path, headers)
    return ret

def expand_url(requested_url):
    requested_url = requested_url.rstrip().rstrip(b'HTTP/1.0').rstrip(b'HTTP/1.1')
    requested_url = requested_url.rstrip()
    if requested_url.startswith(b'http'):
        requested_url = requested_url.lstrip(b'http://')
        index = requested_url.find(b'/')
        host = requested_url[:index]
        # print(f'Host: {host}')
        path = requested_url[index:]
    else:
        host = None
        path = requested_url
    return path, host

def expand_host(requested_host):
    host_parts = requested_host.split(b':')
    host = host_parts[0]
    port = b'80'
    if len(host_parts) == 2:
        port = host_parts[1]
    return host, port

def sanitize_headers(input_headers, host):
    headers = []
    for header in input_headers:
        header = header.split(b': ')
        headers.append((header[0], header[1]))
    headers.insert(0, (b'Host', host))
    return headers

#######################################
# Leave the code below as is.
#######################################



def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.

        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comand-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.


def check_file_name():
    """
    Checks if this file has a valid name for *submission*

    leave this function and as and don't use it. it's just
    to notify you if you're submitting a file with a correct
    name.
    """
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)lab2\.py", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")


def main():
    """
    Please leave the code in this function as is.

    To add code that uses sockets, feel free to add functions
    above main and outside the classes.
    """
    print("\n\n")
    print("*" * 50)
    print(f"[LOG] Printing command line arguments [{', '.join(sys.argv)}]")
    check_file_name()
    print("*" * 50)

    # This argument is optional, defaults to 18888
    proxy_port_number = get_arg(1, 18888)
    while True:
        entry_point(proxy_port_number)


if __name__ == "__main__":
    main()
