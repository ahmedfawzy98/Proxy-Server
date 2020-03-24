# Don't forget to change this file's name before submission.
import sys
import os
import enum
from socket import *
import socket


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
        # Headers will be represented as a list of tuples
        # for example ("Host", "www.google.com")
        # if you get a header as:
        # "Host: www.google.com:80"
        # convert it to ("Host", "www.google.com") note that the
        # port is removed (because it goes into the request_port variable)
        self.headers = headers

    def to_http_string(self):
        """
        Convert the HTTP request/response
        to a valid HTTP string.
        As the protocol specifies:

        [request_line]\r\n
        [header]\r\n
        [headers..]\r\n
        \r\n
        """
        # http_binary = self.method + b' ' + 
        print("*" * 50)
        print("[to_http_string] Implement me!")
        print("*" * 50)
        return None

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(f"Client:", self.client_address_info)
        print(f"Method:", self.method)
        print(f"Host:", self.requested_host)
        print(f"Path:", self.requested_path)
        print(f"Port:", self.requested_port)
        print("Headers:\n", self.headers)


class HttpErrorResponse(object):
    """
    Represents a proxy-error-response.
    """

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
    """
    The values here have nothing to do with
    response values i.e. 400, 502, ..etc.

    Leave this as is, feel free to add yours.
    """
    INVALID_INPUT = 0
    NOT_SUPPORTED = 1
    GOOD = 2
    PLACEHOLDER = -1


def entry_point(proxy_port_number):
    """
    Entry point, start your code here.

    Please don't delete this function,
    but feel free to modify the code
    inside it.
    """

    server = setup_proxy_as_server(proxy_port_number)
    client, address = connect_to_client(server)
    http_raw_data = receive_from_client(server, client, address)
    pipelined = http_request_pipeline(address, http_raw_data)
    if isinstance(pipelined, HttpErrorResponse):
        response_string = pipelined.to_http_string()
        print(response_string)
        client.send(pipelined.to_byte_array(response_string))
        server.close()
    else:
        pass

    return None


def setup_sockets(proxy_port_number):
    """
    Socket logic MUST NOT be written in the any
    class. Classes know nothing about the sockets.

    But feel free to add your own classes/functions.

    Feel free to delete this function.
    """
    print("Starting HTTP proxy on port:", proxy_port_number)


def setup_proxy_as_server(proxy_port_number):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    address = ('127.0.0.1', int(proxy_port_number))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(address)
    s.listen(20)
    return s


def connect_to_client(server):
    client, address = server.accept()
    print(f"Connection from {address} has been established!")
    return client, address

def receive_from_client(server, client, address):
    data = b""
    while True:
        data += client.recv(1024)
        if data.endswith(b'\r\n\r\n'): break
    print(f'Received HTTP_Request = {data}')
    return data


def do_socket_logic():
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.

    Feel free to delete this function.
    """
    pass


def http_request_pipeline(source_addr, http_raw_data):
    """
    HTTP request processing pipeline.

    - Parses the given HTTP request
    - Validates it
    - Returns a sanitized HttpRequestInfo or HttpErrorResponse
        based on request validity.

    returns:
     HttpRequestInfo if the request was parsed correctly.
     HttpErrorResponse if the request was invalid.

    Please don't remove this function, but feel
    free to change its content
    """
    # Parse HTTP request
    parsed = parse_http_request(source_addr, http_raw_data)
    request_status = check_http_request_validity(parsed)
    if is_valid_request(request_status):
        return parsed # sanitize here
    else:
        return appropriate_response(request_status)
    # Validate, sanitize, return Http object.
    # print("*" * 50)
    # print("[http_request_pipeline] Implement me!")
    # print("*" * 50)
    # return None

def is_valid_request(request_state):
    return request_state == HttpRequestState.GOOD

def appropriate_response(request_status):
    if request_status == HttpRequestState.INVALID_INPUT:
        return HttpErrorResponse(b'400', b'Bad Request')
    elif request_status == HttpRequestState.NOT_SUPPORTED:
        return HttpErrorResponse(b'501', b'Not Implemented')

def parse_http_request(source_addr, http_raw_data) -> HttpRequestInfo:
    """
    This function parses an HTTP request into an HttpRequestInfo
    object.

    it does NOT validate the HTTP request.
    """
    http_request = http_raw_data.split(b'\r\n')[:-2]
    method, host, path = parse_request_line(http_request[0])
    headers, host = parse_headers(http_request[1:], host)
    host, port = parse_port(host)
    ret = HttpRequestInfo(source_addr, method, host, port, path, headers)
    # ret.display()
    return ret

def parse_request_line(request_line):
    request_line = request_line.split(b' ')
    method = request_line[0]
    url_or_path = request_line[1]
    if url_or_path.startswith(b'http'):
        url_or_path = url_or_path.lstrip(b'http://')
        url_or_path = url_or_path.split(b'/')
        host = url_or_path[0]
        path = b'/' + url_or_path[1]
    else:
        host = b''
        path = request_line[1]
    return method, host, path

def parse_headers(request_headers, host):
    headers = []
    for header in request_headers:
        # print(f'Header: {header}')
        header = header.split(b': ')
        # print(f'Header splitted: {header}')
        if header[0] == b'Host':
            headers.insert(0, (header[0], header[1]))
        else:
            headers.append((header[0], header[1]))
    return headers, host

def parse_port(host_string):
    host_parts = host_string.split(b':')
    host = host_parts[0]
    port = b'80'
    if len(host_parts) != 1:
        port = host_parts[1]
    return host, port

def check_http_request_validity(http_request_info: HttpRequestInfo) -> HttpRequestState:
    not_supported = [b'PUT', b'PATCH', b'DELETE', b'HEAD', b'POST', b'CONNECT', b'OPTIONS', b'TRACE']
    if http_request_info.method == b'GET':
        return HttpRequestState.GOOD
    elif http_request_info.method in not_supported:
        return HttpRequestState.NOT_SUPPORTED
    else:
        return HttpRequestState.INVALID_INPUT

def sanitize_http_request(request_info: HttpRequestInfo) -> HttpRequestInfo:
    """
    Puts an HTTP request on the sanitized (standard form)

    returns:
    A modified object of the HttpRequestInfo with
    sanitized fields

    for example, expand a URL to relative path + Host header.
    """
    print("*" * 50)
    print("[sanitize_http_request] Implement me!")
    print("*" * 50)
    ret = HttpRequestInfo(None, None, None, None, None, None)
    return ret

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
    entry_point(proxy_port_number)


if __name__ == "__main__":
    main()
