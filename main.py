from abc import ABC, abstractmethod
from typing import Union, Dict, List

import subprocess
import re


class ScannerBase(ABC):
    @abstractmethod
    def run(self, *args, **kwargs) -> Union[list, dict]:
        ...

    @abstractmethod
    def _parse_result(self, *args, **kwargs) -> Union[list, dict]:
        ...


class MassScan(ScannerBase):
    def __init__(self, subnet: str, rate: Union[str, int] = 8000):
        self.subnet = subnet
        self.rate = rate

    def run(self) -> Dict[str, List[str]]:
        """ Запуск masscan
        :return: словать - ключ: хост, значение: список открытых портов
        """
        print(f"[+] Запускаем masscan на {self.subnet}...")

        masscan_cmd = [
            "sudo", "masscan", "-p-", "--rate", str(self.rate), self.subnet
        ]
        try:
            result = subprocess.check_output(masscan_cmd, text=True)
        except subprocess.CalledProcessError as e:
            print(f"[-] Ошибка выполнения masscan: {e}")
            return {}

        print(result)
        return self._parse_result(result=result)

    @staticmethod
    def _parse_result(result: str) -> Dict[str, List[str]]:
        """ Парсинг результатов сканирования
        :param result: результаты сканирования
        :return: словать - ключ: хост, значение: список открытых портов
        """
        open_ports_by_ip = {}

        for line in result.splitlines():
            ip = re.search(r"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}", line).group(0)
            port = re.search(r"(\d+)/(tcp|udp)", line).group(0)
            open_ports_by_ip.setdefault(ip, []).append(port)

        if not open_ports_by_ip:
            print("[-] Открытые порты не найдены!")
            return {}

        return open_ports_by_ip


class NmapScan(ScannerBase):
    def __init__(self, ip_address: str, ports: List[str]):
        self.ip_address = ip_address
        self.ports = ports

    def run(self) -> List[Dict[str, str]]:
        """ Запуск nmap
        :return:
        """
        formatted_ports_str = self._format_ports()
        print(f"[+] Запускаем nmap на {self.ip_address} с портами {formatted_ports_str}...")

        nmap_cmd = [
            "nmap", "-p", formatted_ports_str, "-Pn", "-T4", "--max-retries", "2", self.ip_address
        ]
        try:
            result = subprocess.check_output(nmap_cmd, text=True)
        except subprocess.CalledProcessError as e:
            print(f"[-] Ошибка выполнения nmap: {e}")
            return []

        print(result)
        return self._parse_result(result=result)

    def _format_ports(self) -> str:
        """ Форматирование портов для nmap
        :return:
        """
        return ",".join(str(port.split("/")[0] if "/" in port else port) for port in self.ports)

    @staticmethod
    def _parse_result(result: str) -> List[Dict[str, str]]:
        """ Парсинг результатов сканирования
        :param result: результаты сканирования
        :return:
        """
        scanned_ports = []

        for match in re.findall(r'(\d+)/(tcp|udp)\s+open\s+(\S+)', result):
            port, proto, service = match
            scanned_ports.append({"port": f"{port}/{proto}", "protocol": proto, "banner": service})

        return scanned_ports


def run_scans() -> None:
    """ Запуск сканирований
    :return:
    """
    scan_results = {}

    target = input("[+] Укажите подсеть для сканирования > ")
    masscan = MassScan(subnet=target, rate=8000)
    open_ports_by_ip = masscan.run()
    for ip, ports in open_ports_by_ip.items():
        nmap = NmapScan(ip_address=ip, ports=ports)
        nmap_results = nmap.run()
        scan_results[ip] = nmap_results

    print("[+] Итоговые результаты сканирования:")
    print(scan_results)


if __name__ == '__main__':
    run_scans()

