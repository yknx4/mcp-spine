"""
End-to-end PII scrambling test with a real Postgres MCP server.

This test is intentionally opt-in because it starts a temporary local Postgres
cluster and launches crystaldba/postgres-mcp through Spine.

Run with:
    RUN_POSTGRES_MCP_E2E=1 pytest tests/test_postgres_pii_e2e.py
"""

from __future__ import annotations

import json
import os
import select
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_POSTGRES_MCP_E2E") != "1",
    reason="set RUN_POSTGRES_MCP_E2E=1 to run postgres-mcp e2e test",
)


def _find_command(name: str) -> str | None:
    if found := shutil.which(name):
        return found

    candidates = [
        f"/opt/homebrew/opt/postgresql*/bin/{name}",
        f"/usr/local/opt/postgresql*/bin/{name}",
        f"/Applications/Postgres.app/Contents/Versions/*/bin/{name}",
        f"/usr/lib/postgresql/*/bin/{name}",
    ]
    for pattern in candidates:
        matches = sorted(Path("/").glob(pattern.lstrip("/")))
        if matches:
            return str(matches[-1])
    return None


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603
        cmd,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **kwargs,
    )


def _run_postgres_or_skip(
    cmd: list[str],
    *,
    log_path: Path | None = None,
) -> subprocess.CompletedProcess:
    try:
        return _run(cmd)
    except subprocess.CalledProcessError as exc:
        details = "\n".join(
            part
            for part in [
                exc.stdout or "",
                exc.stderr or "",
                log_path.read_text(encoding="utf-8") if log_path and log_path.exists() else "",
            ]
            if part
        )
        if "could not create shared memory segment" in details or "Operation not permitted" in details:
            pytest.skip(f"local Postgres cannot start in this environment: {details.strip()}")
        raise AssertionError(f"Postgres command failed: {cmd}\n{details}") from exc


def _sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


class SpineClient:
    def __init__(self, config_path: Path):
        self.process = subprocess.Popen(  # noqa: S603
            [sys.executable, "-m", "spine.cli", "serve", "--config", str(config_path)],
            cwd=Path(__file__).resolve().parents[1],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self._next_id = 1

    def close(self) -> None:
        if self.process.poll() is not None:
            return
        assert self.process.stdin is not None
        self.process.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)

    def request(self, method: str, params: dict | None = None, timeout: float = 120) -> dict:
        assert self.process.stdin is not None
        msg_id = self._next_id
        self._next_id += 1
        message = {"jsonrpc": "2.0", "id": msg_id, "method": method}
        if params is not None:
            message["params"] = params

        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()
        return self._read_response(msg_id, timeout=timeout)

    def notify(self, method: str, params: dict | None = None) -> None:
        assert self.process.stdin is not None
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()

    def _read_response(self, msg_id: int, timeout: float) -> dict:
        assert self.process.stdout is not None
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                stderr = self.process.stderr.read() if self.process.stderr else ""
                raise AssertionError(
                    f"spine exited early with {self.process.returncode}:\n{stderr}"
                )

            readable, _, _ = select.select([self.process.stdout], [], [], 0.2)
            if not readable:
                continue

            line = self.process.stdout.readline()
            if not line:
                continue
            response = json.loads(line)
            if response.get("id") == msg_id:
                return response

        stderr = self.process.stderr.read() if self.process.stderr else ""
        raise AssertionError(f"timed out waiting for response id={msg_id}\n{stderr}")


@pytest.fixture
def temp_postgres(tmp_path: Path):
    initdb = _find_command("initdb")
    pg_ctl = _find_command("pg_ctl")
    psql = _find_command("psql")
    missing = [
        name
        for name, cmd in {"initdb": initdb, "pg_ctl": pg_ctl, "psql": psql}.items()
        if not cmd
    ]
    if missing:
        pytest.skip(f"missing local Postgres command(s): {', '.join(missing)}")

    data_dir = tmp_path / "pgdata"
    port = _free_port()
    log_path = tmp_path / "postgres.log"
    socket_dir = Path(tempfile.mkdtemp(prefix="pgsock-", dir="/tmp"))
    password_file = tmp_path / "pg-password"
    password_file.write_text("password\n", encoding="utf-8")

    _run_postgres_or_skip([
        initdb,
        "-D",
        str(data_dir),
        "-A",
        "scram-sha-256",
        "-U",
        "postgres",
        f"--pwfile={password_file}",
        "--no-locale",
    ])
    _run_postgres_or_skip([
        pg_ctl,
        "-D",
        str(data_dir),
        "-l",
        str(log_path),
        "-o",
        f"-p {port} -h 127.0.0.1 -k {socket_dir}",
        "-w",
        "start",
    ], log_path=log_path)

    uri = f"postgresql://postgres:password@127.0.0.1:{port}/postgres"
    try:
        yield {"uri": uri, "psql": psql}
    finally:
        subprocess.run(  # noqa: S603
            [pg_ctl, "-D", str(data_dir), "-m", "fast", "-w", "stop"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        shutil.rmtree(socket_dir, ignore_errors=True)


def _seed_pii_table(psql: str, database_uri: str) -> tuple[list[str], list[str]]:
    try:
        from faker import Faker
    except ImportError:
        pytest.skip("Faker is required for postgres PII e2e data generation")

    fake = Faker("en_US")
    Faker.seed(8675309)

    pii_values = {
        "email": fake.email(),
        "phone": "415-867-5309",
        "ssn": fake.ssn(),
        "credit_card": fake.credit_card_number(card_type="visa"),
        "ip_address": fake.ipv4_public(),
        "mac_address": fake.mac_address(),
        "iban": fake.iban(),
        "homepage_url": fake.url(),
        "postal_code": f"{fake.postcode().split('-')[0]}-4321",
        "birth_date": fake.date_of_birth(minimum_age=25, maximum_age=75).isoformat(),
        "crypto_wallet": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    }
    safe_values = {
        "safe_code": "BOOK-ALPHA",
        "safe_label": "public aggregate row",
        "safe_count": "42",
    }

    values = [*pii_values.values(), *safe_values.values()]
    quoted_values = ", ".join(_sql_literal(value) for value in values)
    sql = """
        DROP TABLE IF EXISTS users;
        CREATE TABLE users (
            id integer PRIMARY KEY,
            email text,
            phone text,
            ssn text,
            credit_card text,
            ip_address text,
            mac_address text,
            iban text,
            homepage_url text,
            postal_code text,
            birth_date text,
            crypto_wallet text,
            safe_code text,
            safe_label text,
            safe_count integer
        );
        INSERT INTO users (
            id,
            email,
            phone,
            ssn,
            credit_card,
            ip_address,
            mac_address,
            iban,
            homepage_url,
            postal_code,
            birth_date,
            crypto_wallet,
            safe_code,
            safe_label,
            safe_count
        )
        VALUES (1, __VALUES__);
    """.replace("__VALUES__", quoted_values)
    _run([psql, database_uri, "-v", "ON_ERROR_STOP=1", "-c", sql])
    return list(pii_values.values()), list(safe_values.values())


def _write_spine_config(tmp_path: Path, database_uri: str) -> Path:
    mcp_command = os.environ.get("POSTGRES_MCP_COMMAND", "uvx")
    if not shutil.which(mcp_command):
        pytest.skip(f"{mcp_command!r} is required to launch postgres-mcp")

    mcp_args = shlex.split(
        os.environ.get("POSTGRES_MCP_ARGS", "postgres-mcp --access-mode=unrestricted")
    )
    config_path = tmp_path / "spine-postgres-pii.toml"
    config_path.write_text(
        f"""
[spine]
log_level = "info"
audit_db = {json.dumps(str(tmp_path / "audit.db"))}

[[servers]]
name = "postgres"
command = {json.dumps(mcp_command)}
args = {json.dumps(mcp_args)}
env = {{ DATABASE_URI = {json.dumps(database_uri)} }}
timeout_seconds = 180
scramble_pii_in_responses = true
scramble_pii_use_nlp = true

[state_guard]
enabled = false

[minifier]
level = 0

[security]
scrub_secrets_in_logs = true
audit_all_tool_calls = true
global_rate_limit = 120
per_tool_rate_limit = 120
""",
        encoding="utf-8",
    )
    return config_path


def _response_text(response: dict) -> str:
    return json.dumps(response, sort_keys=True)


def test_postgres_mcp_responses_do_not_leak_real_pii(tmp_path: Path, temp_postgres):
    pii_values, safe_values = _seed_pii_table(temp_postgres["psql"], temp_postgres["uri"])
    config_path = _write_spine_config(tmp_path, temp_postgres["uri"])
    client = SpineClient(config_path)

    try:
        init = client.request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "postgres-pii-e2e", "version": "1.0"},
        })
        assert "error" not in init
        client.notify("notifications/initialized")

        tools = client.request("tools/list", {}, timeout=180)
        tool_names = {tool["name"] for tool in tools["result"]["tools"]}
        assert "execute_sql" in tool_names

        response = client.request(
            "tools/call",
            {
                "name": "execute_sql",
                "arguments": {
                    "sql": (
                        "SELECT email, phone, ssn, credit_card, ip_address, mac_address, "
                        "iban, homepage_url, postal_code, birth_date, crypto_wallet, "
                        "safe_code, safe_label, safe_count FROM users ORDER BY id"
                    ),
                },
            },
            timeout=180,
        )
        assert "error" not in response

        text = _response_text(response)
        leaked = [value for value in pii_values if value and value in text]
        assert leaked == []

        for value in safe_values:
            assert value in text
    finally:
        client.close()
