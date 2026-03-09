import json
import os
import stat
from pathlib import Path

PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
_UNSAFE_PERMISSION_BITS = stat.S_IRWXG | stat.S_IRWXO


def _is_posix():
    return os.name == "posix"


def _validate_private_permissions(path):
    if not _is_posix() or not path.exists():
        return

    mode = path.stat().st_mode
    if mode & _UNSAFE_PERMISSION_BITS:
        raise PermissionError(
            "Refusing to use insecure cache file permissions for {0}. "
            "Expected owner-only access.".format(path)
        )


def ensure_private_directory(path):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    if _is_posix():
        os.chmod(path, PRIVATE_DIR_MODE)
    _validate_private_permissions(path)
    return path


def load_private_json(path, required_keys=None):
    path = Path(path)
    _validate_private_permissions(path)
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if required_keys:
        missing = [key for key in required_keys if key not in data]
        if missing:
            raise ValueError(
                "Cache file {0} is missing required keys: {1}".format(
                    path, ", ".join(sorted(missing))
                )
            )

    return data


def write_private_json(path, data):
    path = Path(path)
    ensure_private_directory(path.parent)
    temp_path = path.with_name(path.name + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    handle = None

    try:
        fd = os.open(str(temp_path), flags, PRIVATE_FILE_MODE)
        handle = os.fdopen(fd, "w", encoding="utf-8")
        json.dump(data, handle, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        handle = None
        os.replace(temp_path, path)
        if _is_posix():
            os.chmod(path, PRIVATE_FILE_MODE)
        _validate_private_permissions(path)
    finally:
        if handle is not None and not handle.closed:
            handle.close()
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass


def delete_private_file(path):
    path = Path(path)
    if path.exists():
        path.unlink()
