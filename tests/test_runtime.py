from eraseproof import runtime


def test_system_tools_do_not_inherit_bundled_shared_library_path(monkeypatch):
    monkeypatch.setattr(runtime.sys, "frozen", True, raising=False)
    monkeypatch.setenv("LD_LIBRARY_PATH", "/bundle/private/libraries")
    monkeypatch.delenv("LD_LIBRARY_PATH_ORIG", raising=False)
    assert "LD_LIBRARY_PATH" not in runtime.system_environment()
    monkeypatch.setenv("LD_LIBRARY_PATH_ORIG", "/original/system/libraries")
    assert runtime.system_environment()["LD_LIBRARY_PATH"] == "/original/system/libraries"
