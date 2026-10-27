"""Single-process durable job consumer; browser execution always occurs in Docker."""

import asyncio
import json
import re
import threading
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.models import AnalysisResult, SandboxJob, Scan, ThreatIndicator
from app.db.session import AsyncSessionLocal, engine
from app.services.audit import record_activity
from app.services.notifications import create_scan_risk_notification, scan_history_enabled
from app.services.sandbox_runtime import decrypt_target, get_sandbox_status
from app.services.scan_privacy import safe_indicator_description, sanitize_analysis_payload
from app.sandbox.analysis import analyze_observations


POLL_SECONDS = 1.0
ADVISORY_LOCK_ID = 7_345_182_901
MAX_REPORT_BYTES = 1_000_000


def _safe_worker_error(stderr: bytes) -> str:
    """Extract only a Python exception class; never propagate traceback text."""
    names = re.findall(rb"(?m)^([A-Za-z_][A-Za-z0-9_]*(?:Error|Exception|Exit)):", stderr[-8192:])
    allowed = {"ModuleNotFoundError", "ImportError", "PermissionError", "SyntaxError", "RuntimeError", "SystemExit"}
    return names[-1].decode("ascii") if names and names[-1].decode("ascii") in allowed else "UnknownError"


def _container_name(job_id: UUID) -> str:
    return f"scamshield-job-{job_id.hex}"


def execute_browser_job(target: str, job_id: UUID, stop_event: threading.Event | None = None) -> dict:
    """Run a fixed worker command in a disposable, unprivileged container."""
    import docker

    client = docker.from_env()
    name = _container_name(job_id)
    container = None
    try:
        image = client.images.get(settings.sandbox_worker_image)
        network = client.networks.get(settings.sandbox_internal_network)
        if not network.attrs.get("Internal"):
            raise RuntimeError("sandbox_internal_network_not_internal")
        container = client.containers.create(
            image=image.id,
            command=["sleep", str(settings.sandbox_job_timeout_seconds + 20)],
            name=name,
            network=settings.sandbox_internal_network,
            user="pwuser",
            working_dir="/tmp",
            environment={"HOME": "/tmp", "TMPDIR": "/tmp", "PYTHONDONTWRITEBYTECODE": "1"},
            detach=True,
            auto_remove=True,
            read_only=True,
            tmpfs={"/tmp": "rw,noexec,nosuid,nodev,size=32m", "/home/pwuser": "rw,nosuid,nodev,size=64m,uid=1000,gid=1000,mode=0700"},
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            pids_limit=128,
            mem_limit="768m",
            nano_cpus=1_000_000_000,
            shm_size="128m",
            init=True,
            log_config=docker.types.LogConfig(type="none"),
            labels={"com.scamshield.sandbox": "true", "com.scamshield.job": str(job_id)},
        )
        if stop_event is not None and stop_event.is_set():
            raise RuntimeError("sandbox_job_stopped")
        container.start()
        if stop_event is not None and stop_event.is_set():
            raise RuntimeError("sandbox_job_stopped")
        exec_id = client.api.exec_create(
            container.id,
            cmd=["python", "-I", "/opt/scamshield/sandbox_worker.py", "--stdin"],
            stdout=True,
            stderr=True,
            stdin=True,
            user="pwuser",
            workdir="/tmp",
            environment={"HOME": "/tmp", "PYTHONDONTWRITEBYTECODE": "1"},
        )["Id"]
        output_socket = client.api.exec_start(exec_id, detach=False, tty=False, socket=True)
        stdout = bytearray()
        stderr = bytearray()
        try:
            output_socket.sendall(json.dumps({"url": target}, separators=(",", ":")).encode("utf-8") + b"\n")
            from docker.utils.socket import frames_iter

            for stream_id, frame in frames_iter(output_socket, tty=False):
                if stream_id == 1:
                    stdout.extend(frame)
                    if len(stdout) > MAX_REPORT_BYTES:
                        raise RuntimeError("sandbox_report_too_large")
                elif stream_id == 2 and len(stderr) < 16384:
                    stderr.extend(frame[:16384 - len(stderr)])
        finally:
            output_socket.close()
        exit_code = client.api.exec_inspect(exec_id).get("ExitCode")
        if exit_code != 0 or len(stdout) > MAX_REPORT_BYTES:
            raise RuntimeError(f"sandbox_browser_failed:{_safe_worker_error(bytes(stderr))}")
        try:
            result = json.loads(bytes(stdout).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise RuntimeError("sandbox_report_invalid") from None
        if not isinstance(result, dict):
            raise RuntimeError("sandbox_report_invalid")
        if "worker_error" in result:
            error_type = result.get("worker_error")
            if not isinstance(error_type, str) or not error_type.isidentifier():
                error_type = "UnknownError"
            raise RuntimeError(f"sandbox_browser_failed:{error_type}")
        return result
    finally:
        if container is not None:
            try:
                container.remove(force=True, v=True)
            except Exception:
                pass
        client.close()


def kill_browser_job(job_id: UUID) -> None:
    import docker

    client = docker.from_env()
    try:
        try:
            client.containers.get(_container_name(job_id)).kill()
        except docker.errors.NotFound:
            pass
    finally:
        client.close()


async def _claim_next_job() -> UUID | None:
    async with AsyncSessionLocal() as db:
        async with db.begin():
            result = await db.execute(
                select(SandboxJob)
                .where(SandboxJob.state == "queued", SandboxJob.cancel_requested.is_(False))
                .order_by(SandboxJob.updated_at, SandboxJob.id)
                .with_for_update(skip_locked=True)
                .limit(1)
            )
            job = result.scalar_one_or_none()
            if job is None:
                return None
            scan = await db.get(Scan, job.scan_id)
            if scan is None:
                job.state = "failed"
                job.error_code = "scan_record_missing"
                job.target_encrypted = None
                job.completed_at = datetime.now(timezone.utc)
                return None
            if not await scan_history_enabled(db, scan.user_id):
                await db.delete(scan)
                return None
            now = datetime.now(timezone.utc)
            job.state = "provisioning"
            job.started_at = now
            job.updated_at = now
            scan.status = "provisioning"
        return job.id


async def _is_cancelled(job_id: UUID) -> bool:
    async with AsyncSessionLocal() as db:
        job = await db.get(SandboxJob, job_id)
        return job is None or job.cancel_requested


async def _finish_failure(job_id: UUID, state: str, error_code: str) -> None:
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        async with db.begin():
            job = await db.get(SandboxJob, job_id, with_for_update=True)
            if job is None:
                return
            scan = await db.get(Scan, job.scan_id)
            job.state = state
            job.error_code = error_code
            job.target_encrypted = None
            job.completed_at = now
            job.updated_at = now
            if scan is not None:
                scan.status = state
                scan.completed_at = now


async def _process_job(job_id: UUID) -> None:
    async with AsyncSessionLocal() as db:
        job = await db.get(SandboxJob, job_id)
        if job is None or not job.target_encrypted:
            await _finish_failure(job_id, "failed", "sandbox_target_unavailable")
            return
        try:
            target = decrypt_target(job.target_encrypted)
        except RuntimeError:
            await _finish_failure(job_id, "failed", "sandbox_target_unreadable")
            return
        scan = await db.get(Scan, job.scan_id)
        if scan is None:
            await _finish_failure(job_id, "failed", "scan_record_missing")
            return
        if not await scan_history_enabled(db, scan.user_id):
            await db.delete(scan)
            await db.commit()
            return
        scan.status = "running"
        job.state = "running"
        job.updated_at = datetime.now(timezone.utc)
        await db.commit()

    stop_event = threading.Event()
    task = asyncio.create_task(asyncio.to_thread(execute_browser_job, target, job_id, stop_event))
    deadline = asyncio.get_running_loop().time() + settings.sandbox_job_timeout_seconds
    terminal_state = None
    while not task.done():
        if asyncio.get_running_loop().time() >= deadline:
            terminal_state = "timed_out"
            stop_event.set()
            break
        if await _is_cancelled(job_id):
            terminal_state = "blocked"
            stop_event.set()
            break
        await asyncio.sleep(0.5)

    if terminal_state:
        for _ in range(20):
            if task.done():
                break
            try:
                await asyncio.to_thread(kill_browser_job, job_id)
            except Exception:
                pass
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=0.25)
            except (asyncio.TimeoutError, Exception):
                pass
        if task.done():
            try:
                await task
            except Exception:
                pass
        await _finish_failure(job_id, terminal_state, "cancelled" if terminal_state == "blocked" else "timeout")
        return

    try:
        observations = await task
    except Exception:
        await _finish_failure(job_id, "failed", "sandbox_worker_failed")
        return

    async with AsyncSessionLocal() as db:
        job = await db.get(SandboxJob, job_id, with_for_update=True)
        scan = await db.get(Scan, job.scan_id) if job is not None else None
        if job is None or scan is None:
            return
        if not await scan_history_enabled(db, scan.user_id):
            await db.delete(scan)
            await db.commit()
            return
        job.state = "collecting_evidence"
        scan.status = "collecting_evidence"
        job.updated_at = datetime.now(timezone.utc)
        job.observations = sanitize_analysis_payload(observations)
        await db.commit()

    async with AsyncSessionLocal() as db:
        async with db.begin():
            job = await db.get(SandboxJob, job_id, with_for_update=True)
            scan = await db.get(Scan, job.scan_id) if job is not None else None
            if job is None or scan is None:
                return
            if not await scan_history_enabled(db, scan.user_id):
                await db.delete(scan)
                return
            job.state = "analyzing"
            scan.status = "analyzing"
            job.updated_at = datetime.now(timezone.utc)

    report = analyze_observations(observations)
    safe_observations = sanitize_analysis_payload(observations)
    safe_report = sanitize_analysis_payload(report)
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        async with db.begin():
            job = await db.get(SandboxJob, job_id, with_for_update=True)
            if job is None:
                return
            scan = await db.get(Scan, job.scan_id)
            if scan is None:
                return
            if not await scan_history_enabled(db, scan.user_id):
                await db.delete(scan)
                continue_job = False
            else:
                continue_job = True
                job.observations = safe_observations
                job.report = safe_report
                score = int(report["risk_score"])
                classification = report["classification"]
                scan.risk_score = score
                scan.status = classification
                scan.confidence = None
                scan.threat_type = None
                scan.completed_at = now
                job.state = "completed"
                job.target_encrypted = None
                job.completed_at = now
                db.add(AnalysisResult(
                    scan_id=scan.id,
                    model_name="sandbox-rules",
                    model_version=report["method"]["ruleset_version"],
                    prediction=classification,
                    probability=score / 100,
                    features={"observation_count": len(observations.get("requests", [])), "ruleset_version": report["method"]["ruleset_version"]},
                    explanation={"findings": report["findings"], "conclusion": report["conclusion"]},
                ))
                for finding in report["findings"]:
                    db.add(ThreatIndicator(
                        scan_id=scan.id,
                        indicator_type=finding["id"],
                        description=safe_indicator_description(finding["id"]),
                        severity=finding["severity"],
                        evidence={"observation_refs": finding["observation_refs"], "rule": finding["rule"]},
                    ))
                record_activity(db, scan.user_id, "scan_completed")
                if classification == "critical":
                    record_activity(db, scan.user_id, "scan_critical_risk")
                elif classification == "high":
                    record_activity(db, scan.user_id, "scan_high_risk")
                await create_scan_risk_notification(db, scan.user_id, classification, scan.id)
        if not continue_job:
            return


async def _startup_recovery() -> None:
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        async with db.begin():
            result = await db.execute(
                update(SandboxJob)
                .where(SandboxJob.state.in_(["provisioning", "running", "collecting_evidence", "analyzing"]))
                .values(state="failed", error_code="worker_restarted", target_encrypted=None, completed_at=now, updated_at=now)
                .returning(SandboxJob.scan_id)
            )
            scan_ids = [row[0] for row in result.all()]
            if scan_ids:
                await db.execute(update(Scan).where(Scan.id.in_(scan_ids)).values(status="failed", completed_at=now))
    import docker

    client = docker.from_env()
    try:
        for container in client.containers.list(all=True, filters={"label": "com.scamshield.sandbox=true"}):
            try:
                container.remove(force=True, v=True)
            except docker.errors.NotFound:
                pass
    finally:
        client.close()


async def run_worker() -> None:
    lock_connection = await engine.connect()
    try:
        lock = await lock_connection.execute(text("SELECT pg_try_advisory_lock(:lock_id)"), {"lock_id": ADVISORY_LOCK_ID})
        if not lock.scalar_one():
            raise RuntimeError("A sandbox worker is already running.")
        await lock_connection.commit()
        await _startup_recovery()
        while True:
            if not get_sandbox_status().available:
                await asyncio.sleep(POLL_SECONDS)
                continue
            job_id = await _claim_next_job()
            if job_id is None:
                await asyncio.sleep(POLL_SECONDS)
                continue
            await _process_job(job_id)
    finally:
        try:
            await lock_connection.execute(text("SELECT pg_advisory_unlock(:lock_id)"), {"lock_id": ADVISORY_LOCK_ID})
            await lock_connection.commit()
        finally:
            await lock_connection.close()


def main() -> None:
    asyncio.run(run_worker())


if __name__ == "__main__":
    main()
