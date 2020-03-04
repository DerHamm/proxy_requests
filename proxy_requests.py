import requests
from random import randint

from bs4 import BeautifulSoup


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class Sockets(list, metaclass=Singleton):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def append(self, *args, **kwargs):
        if len(args) >= 2:
            raise ValueError('Cannot pass multiple value into sockets list (yet)')

        # Don't let duplicates into the list
        if args[0] not in self:
            super().append(*args, **kwargs)


def url_generator():
    yield 'https://free-proxy-list.net/'
    yield 'https://www.sslproxies.org/'
    yield 'https://www.us-proxy.org/'


class ProxyRequests(object):

    def __init__(self, url):
        self.URLS = url_generator()
        self.sockets = Sockets()
        self.url = url
        self.request, self.proxy = '', ''
        self.proxy_used, self.raw_content = '', ''
        self.status_code = 0
        self.headers, self.file_dict = {}, {}
        self.json = None
        self.timeout = 8.0
        self.errs = ('ConnectTimeout', 'ProxyError', 'SSLError')

    def acquire_sockets(self):
        try:
            r = requests.get(next(self.URLS))
            while r.status_code != 200:
                r = requests.get(next(self.URLS))
        except StopIteration:
            return self.acquire_sockets()
        finally:
            self.URLS = url_generator()

        # New approach
        soup = BeautifulSoup(r.text, 'html.parser')

        # We will get ip, port and country if we search for columns without a class
        entries = soup.find_all('td', class_='')
        sockets = Sockets()
        loop_range = int(len(entries) / 3)
        for i in range(0, loop_range, 4):
            ip_tag = entries[i].__str__()
            port_tag = entries[i + 1].__str__()

            ip = ip_tag[4:len(ip_tag) - 5]
            port = port_tag[4:len(port_tag) - 5]

            socket_string = '{}:{}'.format(ip, port)
            sockets.append(socket_string)

        self.sockets = sockets

    def set_request_data(self, req, socket):
        self.request = req.text
        self.headers = req.headers
        self.status_code = req.status_code
        self.raw_content = req.content
        self.proxy_used = socket
        try:
            self.json = req.json()
        except Exception:
            self.json = {}

    def rand_sock(self):
        return randint(0, len(self.sockets) - 1)

    def is_err(self, err):
        if type(err).__name__ not in self.errs:
            raise err

    def limit_succeeded(self):
        print('Limit succeeded, trying to gather more proxies')
        self.acquire_sockets()

    def get(self):
        if len(self.sockets) > 0:
            current_socket = self.sockets.pop(self.rand_sock())
            proxies = {
                'http': 'http://' + current_socket,
                'https': 'https://' + current_socket
            }
            try:
                request = requests.get(
                    self.url,
                    timeout=self.timeout,
                    proxies=proxies)
                self.set_request_data(request, current_socket)
            except Exception as e:
                self.is_err(e)
                self.get()
        else:
            self.limit_succeeded()

    def get_with_headers(self):
        if len(self.sockets) > 0:
            current_socket = self.sockets.pop(self.rand_sock())
            proxies = {
                'http': 'http://' + current_socket,
                'https': 'https://' + current_socket
            }
            try:
                request = requests.get(
                    self.url,
                    timeout=self.timeout,
                    proxies=proxies,
                    headers=self.headers)
                self.set_request_data(request, current_socket)
            except Exception as e:
                self.is_err(e)
                self.get_with_headers()
        else:
            self.limit_succeeded()

    def post(self, data):
        if len(self.sockets) > 0:
            current_socket = self.sockets.pop(self.rand_sock())
            proxies = {
                'http': 'http://' + current_socket,
                'https': 'https://' + current_socket
            }
            try:
                request = requests.post(
                    self.url,
                    json=data,
                    timeout=self.timeout,
                    proxies=proxies)
                self.set_request_data(request, current_socket)
            except Exception as e:
                self.is_err(e)
                self.post(data)
            else:
                self.limit_succeeded()

    def post_with_headers(self, data):
        if len(self.sockets) > 0:
            current_socket = self.sockets.pop(self.rand_sock())
            proxies = {
                'http': 'http://' + current_socket,
                'https': 'https://' + current_socket
            }
            try:
                request = requests.post(
                    self.url,
                    json=data,
                    timeout=self.timeout,
                    headers=self.headers,
                    proxies=proxies)
                self.set_request_data(request, current_socket)
            except Exception as e:
                self.is_err(e)
                self.post_with_headers(data)
        else:
            self.limit_succeeded()

    def post_file(self):
        if len(self.sockets) > 0:
            current_socket = self.sockets.pop(self.rand_sock())
            proxies = {
                'http': 'http://' + current_socket,
                'https': 'https://' + current_socket
            }
            try:
                request = requests.post(
                    self.url,
                    files=self.file_dict,
                    timeout=self.timeout,
                    proxies=proxies)
                self.set_request_data(request, current_socket)
            except Exception as e:
                self.is_err(e)
                self.post_file()
        else:
            self.limit_succeeded()

    def post_file_with_headers(self):
        if len(self.sockets) > 0:
            current_socket = self.sockets.pop(self.rand_sock())
            proxies = {
                'http': 'http://' + current_socket,
                'https': 'https://' + current_socket
            }
            try:
                request = requests.post(
                    self.url,
                    files=self.file_dict,
                    timeout=self.timeout,
                    headers=self.headers,
                    proxies=proxies)
                self.set_request_data(request, current_socket)
            except Exception as e:
                self.is_err(e)
                self.post_file_with_headers()
        else:
            self.limit_succeeded()

    def get_headers(self):
        return self.headers

    def set_headers(self, outgoing_headers):
        self.headers = outgoing_headers

    def set_file(self, outgoing_file):
        self.file_dict = outgoing_file

    def get_status_code(self):
        return self.status_code

    def get_proxy_used(self):
        return str(self.proxy_used)

    def get_raw(self):
        return self.raw_content

    def get_json(self):
        return self.json

    def __str__(self):
        return str(self.request)


class ProxyRequestsBasicAuth(ProxyRequests):
    def __init__(self, url, username, password):
        super().__init__(url)
        self.username = username
        self.password = password

    def get(self):
        if len(self.sockets) > 0:
            current_socket = self.sockets.pop(self.rand_sock())
            proxies = {
                'http': 'http://' + current_socket,
                'https': 'https://' + current_socket
            }
            try:
                request = requests.get(
                    self.url,
                    auth=(self.username, self.password),
                    timeout=self.timeout,
                    proxies=proxies)
                self.set_request_data(request, current_socket)
            except Exception as e:
                self.is_err(e)
                self.get()
        else:
            self.limit_succeeded()

    def get_with_headers(self):
        if len(self.sockets) > 0:
            current_socket = self.sockets.pop(self.rand_sock())
            proxies = {
                'http': 'http://' + current_socket,
                'https': 'https://' + current_socket
            }
            try:
                request = requests.get(
                    self.url,
                    auth=(self.username, self.password),
                    timeout=self.timeout,
                    proxies=proxies,
                    headers=self.headers)
                self.set_request_data(request, current_socket)
            except Exception as e:
                self.is_err(e)
                self.get_with_headers()
        else:
            self.limit_succeeded()

    def post(self, data):
        if len(self.sockets) > 0:
            current_socket = self.sockets.pop(self.rand_sock())
            proxies = {
                'http': 'http://' + current_socket,
                'https': 'https://' + current_socket
            }
            try:
                request = requests.post(
                    self.url,
                    json=data,
                    auth=(self.username, self.password),
                    timeout=self.timeout,
                    proxies=proxies)
                self.set_request_data(request, current_socket)
            except Exception as e:
                self.is_err(e)
                self.post(data)
        else:
            self.limit_succeeded()

    def post_with_headers(self, data):
        if len(self.sockets) > 0:
            current_socket = self.sockets.pop(self.rand_sock())
            proxies = {
                'http': 'http://' + current_socket,
                'https': 'https://' + current_socket
            }
            try:
                request = requests.post(
                    self.url,
                    json=data,
                    auth=(self.username, self.password),
                    timeout=self.timeout,
                    headers=self.headers,
                    proxies=proxies)
                self.set_request_data(request, current_socket)
            except Exception as e:
                self.is_err(e)
                self.post_with_headers(data)
        else:
            self.limit_succeeded()

    def post_file(self):
        if len(self.sockets) > 0:
            current_socket = self.sockets.pop(self.rand_sock())
            proxies = {
                'http': 'http://' + current_socket,
                'https': 'https://' + current_socket
            }
            try:
                request = requests.post(
                    self.url,
                    files=self.file_dict,
                    auth=(self.username, self.password),
                    timeout=self.timeout,
                    proxies=proxies)
                self.set_request_data(request, current_socket)
            except Exception as e:
                self.is_err(e)
                self.post_file()
        else:
            self.limit_succeeded()

    def post_file_with_headers(self):
        if len(self.sockets) > 0:
            current_socket = self.sockets.pop(self.rand_sock())
            proxies = {
                'http': 'http://' + current_socket,
                'https': 'https://' + current_socket
            }
            try:
                request = requests.post(
                    self.url,
                    files=self.file_dict,
                    auth=(self.username, self.password),
                    timeout=self.timeout,
                    headers=self.headers,
                    proxies=proxies)
                self.set_request_data(request, current_socket)
            except Exception as e:
                self.is_err(e)
                self.post_file_with_headers()
        else:
            self.limit_succeeded()


class PoolSucceeded(Exception):
    pass


