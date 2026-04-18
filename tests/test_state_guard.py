"""Tests for the State Guard (Stage 4)."""


from spine.state_guard import StateGuard


class TestFileTracking:
    def test_tracks_new_file(self, tmp_path):
        f = tmp_path / "main.py"
        f.write_text("print('hello')")

        guard = StateGuard(watch_paths=[str(tmp_path)])
        assert guard.update_file(str(f))
        assert str(f) in guard.manifest
        assert guard.manifest[str(f)].size == len("print('hello')")

    def test_detects_content_change(self, tmp_path):
        f = tmp_path / "main.py"
        f.write_text("v1")

        guard = StateGuard(watch_paths=[str(tmp_path)])
        guard.update_file(str(f))
        sha_v1 = guard.manifest[str(f)].sha256

        f.write_text("v2")
        assert guard.update_file(str(f))
        sha_v2 = guard.manifest[str(f)].sha256

        assert sha_v1 != sha_v2
        assert guard.manifest[str(f)].version == 2

    def test_ignores_unchanged_content(self, tmp_path):
        f = tmp_path / "main.py"
        f.write_text("same content")

        guard = StateGuard(watch_paths=[str(tmp_path)])
        guard.update_file(str(f))
        assert not guard.update_file(str(f))  # same content

    def test_removes_deleted_file(self, tmp_path):
        f = tmp_path / "temp.py"
        f.write_text("temp")

        guard = StateGuard(watch_paths=[str(tmp_path)])
        guard.update_file(str(f))
        assert guard.remove_file(str(f))
        assert str(f) not in guard.manifest

    def test_ignores_patterns(self, tmp_path):
        git_file = tmp_path / ".git" / "HEAD"
        git_file.parent.mkdir()
        git_file.write_text("ref: refs/heads/main")

        guard = StateGuard(
            watch_paths=[str(tmp_path)],
            ignore_patterns=["**/.git/**"],
        )
        assert not guard.update_file(str(git_file))
        assert str(git_file) not in guard.manifest

    def test_max_tracked_files(self, tmp_path):
        guard = StateGuard(
            watch_paths=[str(tmp_path)],
            max_tracked_files=3,
        )

        for i in range(5):
            f = tmp_path / f"file{i}.py"
            f.write_text(f"content {i}")
            guard.update_file(str(f))

        assert len(guard.manifest) <= 3


class TestVersioning:
    def test_monotonic_versions(self, tmp_path):
        guard = StateGuard(watch_paths=[str(tmp_path)])
        versions = []

        for i in range(5):
            f = tmp_path / f"file{i}.py"
            f.write_text(f"content {i}")
            guard.update_file(str(f))
            versions.append(guard.current_version)

        assert versions == sorted(versions)
        assert len(set(versions)) == 5  # all unique

    def test_get_changed_since(self, tmp_path):
        guard = StateGuard(watch_paths=[str(tmp_path)])

        f1 = tmp_path / "a.py"
        f1.write_text("a")
        guard.update_file(str(f1))
        checkpoint = guard.current_version

        f2 = tmp_path / "b.py"
        f2.write_text("b")
        guard.update_file(str(f2))

        changed = guard.get_changed_since(checkpoint)
        assert len(changed) == 1
        assert changed[0].path == str(f2)


class TestStatePin:
    def test_empty_manifest_no_pin(self):
        guard = StateGuard()
        assert guard.generate_pin() == ""

    def test_pin_contains_file_info(self, tmp_path):
        f = tmp_path / "main.py"
        f.write_text("def main(): pass")

        guard = StateGuard(watch_paths=[str(tmp_path)])
        guard.update_file(str(f))

        pin = guard.generate_pin()
        assert "spine-state" in pin
        assert "sha:" in pin
        assert "v1" in pin
        assert "Re-read before editing" in pin

    def test_pin_ordered_by_recency(self, tmp_path):
        guard = StateGuard(watch_paths=[str(tmp_path)])

        f1 = tmp_path / "old.py"
        f1.write_text("old")
        guard.update_file(str(f1))

        f2 = tmp_path / "new.py"
        f2.write_text("new")
        guard.update_file(str(f2))

        pin = guard.generate_pin()
        # "new.py" should appear before "old.py"
        assert pin.index("new.py") < pin.index("old.py")

    def test_pin_caps_at_max(self, tmp_path):
        guard = StateGuard(
            watch_paths=[str(tmp_path)],
            max_pin_files=2,
        )

        for i in range(5):
            f = tmp_path / f"file{i}.py"
            f.write_text(f"content {i}")
            guard.update_file(str(f))

        pin = guard.generate_pin()
        # Should only list 2 files (most recent)
        file_lines = [l for l in pin.split("\n") if l.strip().startswith("file")]
        assert len(file_lines) <= 2


class TestPinInjection:
    def test_injects_into_dict_response(self, tmp_path):
        f = tmp_path / "x.py"
        f.write_text("x")
        guard = StateGuard(watch_paths=[str(tmp_path)])
        guard.update_file(str(f))

        response = {
            "result": {
                "content": [{"type": "text", "text": "File contents here"}],
            }
        }
        injected = guard.inject_pin_into_response(response)
        content = injected["result"]["content"]
        assert len(content) == 2  # original + pin
        assert "spine-state" in content[1]["text"]

    def test_no_injection_on_empty_manifest(self):
        guard = StateGuard()
        response = {"result": {"content": [{"type": "text", "text": "hi"}]}}
        result = guard.inject_pin_into_response(response)
        assert len(result["result"]["content"]) == 1  # unchanged


class TestSnapshot:
    def test_snapshot_returns_hashes(self, tmp_path):
        guard = StateGuard(watch_paths=[str(tmp_path)])

        f = tmp_path / "a.py"
        f.write_text("hello")
        guard.update_file(str(f))

        snap = guard.snapshot()
        assert str(f) in snap
        assert len(snap[str(f)]) == 64  # SHA-256 hex
