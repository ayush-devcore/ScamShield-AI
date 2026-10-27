"""Harmless Docker network gate. Exit non-zero unless every isolation probe passes."""

from __future__ import annotations

import json
import socket
import socketserver
import sys
import threading
from pathlib import Path

import docker

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.core.config import settings


PROBE_CODE = r'''import json,socket,ssl,urllib.request
def tcp(host,port):
    try:
        s=socket.create_connection((host,port),timeout=2); s.close(); return True
    except OSError: return False
def proxy_status(authority):
    try:
        s=socket.create_connection(("egress-proxy",8080),timeout=3); s.settimeout(3)
        request=("GET http://"+authority+"/ HTTP/1.1\r\nHost: "+authority+"\r\nConnection: close\r\n\r\n").encode()
        s.sendall(request); first=s.recv(128).split(b"\r\n",1)[0]; s.close()
        return int(first.split()[1])
    except Exception: return 0
def dns():
    q=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2)
    try: s.sendto(q,("8.8.8.8",53)); s.recvfrom(512); return True
    except OSError: return False
    finally: s.close()
def udp(host,port,marker):
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(marker,(host,port)); s.close()
    except OSError: pass
proxy=urllib.request.ProxyHandler({"http":"http://egress-proxy:8080"})
opener=urllib.request.build_opener(proxy)
try:
    with opener.open("http://example.com/",timeout=12) as response: proxy_egress_status=response.status
except Exception: proxy_egress_status=0
print(json.dumps({
  "direct_public_ip_blocked": not tcp("1.1.1.1",443),
  "direct_public_ipv6_blocked": not tcp("2606:4700:4700::1111",443),
  "direct_public_hostname_blocked": not tcp("example.com",80),
  "direct_dns_blocked": not dns(),
  "host_gateway_blocked": not tcp(__GATEWAY__,__PORT__),
  "host_docker_internal_blocked": not tcp("host.docker.internal",__PORT__),
  "_udp_gateway_probe": (udp(__GATEWAY__,__UDP_PORT__,b"gateway"), udp("host.docker.internal",__UDP_PORT__,b"alias")),
  "proxy_egress_works": proxy_egress_status in (200,301,302,307,308),
  "proxy_blocks_loopback": proxy_status("127.0.0.1") == 403,
  "proxy_blocks_metadata_ip": proxy_status("169.254.169.254") == 403,
  "proxy_blocks_nonstandard_port": proxy_status("example.com:8080") == 403,
},separators=(",",":")))'''


class _QuietHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.close()


class _QuietServer(socketserver.TCPServer):
    allow_reuse_address = True


class _QuietUdpServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class _QuietUdpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, _address = self.request
        if data in (b"gateway", b"alias"):
            self.server.received.add(data)


def verify() -> dict[str, bool]:
    server = _QuietServer(("0.0.0.0", 0), _QuietHandler)
    udp_server = _QuietUdpServer(("0.0.0.0", 0), _QuietUdpHandler)
    udp_server.received = set()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    udp_thread = threading.Thread(target=udp_server.serve_forever, daemon=True)
    thread.start()
    udp_thread.start()
    client = docker.from_env()
    container = None
    try:
        network = client.networks.get(settings.sandbox_internal_network)
        network.reload()
        if not network.attrs.get("Internal"):
            raise RuntimeError("The browser network is not configured as internal.")
        egress_network = client.networks.get(settings.sandbox_egress_network)
        egress_network.reload()
        if egress_network.attrs.get("Internal"):
            raise RuntimeError("The proxy egress network is unexpectedly internal.")
        proxy = client.containers.get(settings.sandbox_proxy_container)
        proxy.reload()
        proxy_networks = proxy.attrs.get("NetworkSettings", {}).get("Networks", {})
        health = proxy.attrs.get("State", {}).get("Health", {}).get("Status")
        if proxy.status != "running" or health != "healthy":
            raise RuntimeError("The restricted egress proxy is not healthy.")
        if set(proxy_networks) != {settings.sandbox_internal_network, settings.sandbox_egress_network}:
            raise RuntimeError("The egress proxy network attachments are unexpected.")
        gateway = network.attrs.get("IPAM", {}).get("Config", [{}])[0].get("Gateway")
        if not gateway:
            raise RuntimeError("Docker did not expose an internal-network gateway for testing.")
        host_port = server.server_address[1]
        probe = (PROBE_CODE.replace("__GATEWAY__", repr(gateway)).replace("__PORT__", str(host_port))
                 .replace("__UDP_PORT__", str(udp_server.server_address[1])))
        image = client.images.get(settings.sandbox_worker_image)
        container = client.containers.create(
            image=image.id,
            entrypoint=["python"],
            command=["-c", probe],
            network=settings.sandbox_internal_network,
            extra_hosts={"host.docker.internal": "host-gateway"},
            user="pwuser",
            read_only=True,
            tmpfs={"/tmp": "rw,nosuid,nodev,size=16m"},
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            pids_limit=64,
            mem_limit="256m",
            nano_cpus=500_000_000,
            labels={"com.scamshield.network-probe": "true"},
        )
        container.start()
        try:
            container.wait(timeout=35)
            response = json.loads(container.logs(stdout=True, stderr=False).decode("utf-8").strip())
        except Exception as exc:
            raise RuntimeError("The isolated network probe did not finish safely.") from exc
        attached = set(container.attrs.get("NetworkSettings", {}).get("Networks", {}))
        if attached != {settings.sandbox_internal_network}:
            raise RuntimeError("The browser probe unexpectedly received another network interface.")
        if container.attrs.get("Mounts"):
            raise RuntimeError("The browser probe unexpectedly received a host mount.")
        response["udp_host_gateway_blocked"] = b"gateway" not in udp_server.received
        response["udp_host_docker_internal_blocked"] = b"alias" not in udp_server.received
        response.pop("_udp_gateway_probe", None)
        return response
    finally:
        if container is not None:
            try:
                container.remove(force=True, v=True)
            except Exception:
                pass
        client.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        udp_server.shutdown()
        udp_server.server_close()
        udp_thread.join(timeout=2)


if __name__ == "__main__":
    try:
        results = verify()
        for test_name, passed in sorted(results.items()):
            print(f"{'PASS' if passed else 'FAIL'} {test_name}")
        raise SystemExit(0 if results and all(results.values()) else 1)
    except Exception as exc:
        print(f"FAIL sandbox_network_probe ({type(exc).__name__})")
        raise SystemExit(1)
