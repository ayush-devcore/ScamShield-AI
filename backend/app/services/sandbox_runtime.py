"""Fail-closed checks and encrypted target handling for the sandbox runtime."""

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings
from app.schemas.sandbox import SandboxCapabilities, SandboxStatusResponse


def _cipher() -> Fernet | None:
    if not settings.sandbox_encryption_key:
        return None
    try:
        return Fernet(settings.sandbox_encryption_key.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        return None


def encrypt_target(target: str) -> str:
    cipher = _cipher()
    if cipher is None:
        raise RuntimeError("sandbox_encryption_key_unavailable")
    return cipher.encrypt(target.encode("utf-8")).decode("ascii")


def decrypt_target(target: str) -> str:
    cipher = _cipher()
    if cipher is None:
        raise RuntimeError("sandbox_encryption_key_unavailable")
    try:
        return cipher.decrypt(target.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError, ValueError):
        raise RuntimeError("sandbox_target_unreadable") from None


def get_sandbox_status() -> SandboxStatusResponse:
    capabilities = SandboxCapabilities(
        url_browser_runtime=False,
        restricted_egress=False,
        file_static_analysis=False,
        file_detonation=False,
    )
    if not settings.sandbox_runtime_enabled:
        return SandboxStatusResponse(
            status="runtime_unavailable",
            available=False,
            reason="sandbox_runtime_disabled",
            message="URL execution is disabled until the restricted runtime is configured and verified.",
            capabilities=capabilities,
        )
    if not settings.sandbox_network_verified:
        return SandboxStatusResponse(
            status="runtime_unavailable",
            available=False,
            reason="network_isolation_not_verified",
            message="URL execution remains disabled until host-gateway, direct-egress, and proxy-bypass checks pass.",
            capabilities=capabilities,
        )
    if _cipher() is None:
        return SandboxStatusResponse(
            status="runtime_unavailable",
            available=False,
            reason="sandbox_encryption_key_unavailable",
            message="URL execution requires a valid sandbox target-encryption key.",
            capabilities=capabilities,
        )
    try:
        import docker

        client = docker.from_env()
        try:
            client.ping()
            client.images.get(settings.sandbox_worker_image)
            internal = client.networks.get(settings.sandbox_internal_network)
            egress = client.networks.get(settings.sandbox_egress_network)
            proxy = client.containers.get(settings.sandbox_proxy_container)
            proxy.reload()
            internal.reload()
            egress.reload()
            proxy_networks = proxy.attrs.get("NetworkSettings", {}).get("Networks", {})
            proxy_state = proxy.attrs.get("State", {})
            internal_ok = bool(internal.attrs.get("Internal"))
            egress_ok = not bool(egress.attrs.get("Internal"))
            proxy_ok = (
                proxy.status == "running"
                and settings.sandbox_internal_network in proxy_networks
                and settings.sandbox_egress_network in proxy_networks
                and set(proxy_networks) == {settings.sandbox_internal_network, settings.sandbox_egress_network}
                and proxy_state.get("Health", {}).get("Status") == "healthy"
            )
            if not (internal_ok and egress_ok and proxy_ok):
                raise RuntimeError("sandbox_topology_incomplete")
        finally:
            client.close()
    except Exception:
        return SandboxStatusResponse(
            status="runtime_unavailable",
            available=False,
            reason="sandbox_topology_unavailable",
            message="The verified internal network, egress filter, worker image, or Docker engine is unavailable.",
            capabilities=capabilities,
        )
    return SandboxStatusResponse(
        status="available",
        available=True,
        reason=None,
        message="The disposable browser runtime and restricted egress topology are ready.",
        capabilities=SandboxCapabilities(
            url_browser_runtime=True,
            restricted_egress=True,
            file_static_analysis=False,
            file_detonation=False,
        ),
    )
