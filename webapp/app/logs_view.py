"""Read bounded excerpts of local log files for administrators."""

from contextlib import contextmanager
from dataclasses import dataclass
import os
import stat

from flask import abort, current_app, make_response, request
from flask_appbuilder import BaseView, expose, has_access

from .logging_config import configured_log_directory

LOG_PAGE_BYTES = 256 * 1024


@dataclass(frozen=True)
class LogPage:
    """An excerpt and its byte offsets in the selected file."""

    text: str
    start: int
    end: int
    size: int


@contextmanager
def _open_descriptor(path, flags, *, dir_fd=None):
    """Hold a read-only descriptor for the duration of one request operation."""
    descriptor = os.open(path, os.O_RDONLY | flags, dir_fd=dir_fd)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def _list_logs(directory):
    files = []
    with os.scandir(directory) as entries:
        for entry in entries:
            if not entry.name.endswith(".log") or not entry.name.isprintable():
                continue
            try:
                info = entry.stat(follow_symlinks=False)
            except FileNotFoundError:
                continue  # Rotation can remove an entry during listing.
            if stat.S_ISREG(info.st_mode):
                files.append((info.st_mtime_ns, entry.name))
    return [name for _, name in sorted(files, reverse=True)]


def _offset(name):
    """Read an optional byte offset without accepting unbounded integers."""
    value = request.args.get(name)
    if value is None:
        return None
    if not (len(value) <= 19 and value.isascii() and value.isdecimal()):
        abort(400)
    return int(value)


def _read_log_page(directory, name, before, after):
    # O_NONBLOCK also avoids hanging if a regular file is replaced by a FIFO.
    flags = os.O_NOFOLLOW | os.O_NONBLOCK
    with _open_descriptor(name, flags, dir_fd=directory) as source:
        info = os.fstat(source)
        if not stat.S_ISREG(info.st_mode):
            raise FileNotFoundError(name)
        size = info.st_size
        if after is not None and after < size:
            start = after
            stop = min(size, start + LOG_PAGE_BYTES)
            content = os.pread(source, stop - start, start)
            if stop < size:
                boundary = content.rfind(b"\n") + 1
                if boundary:
                    content = content[:boundary]
        else:
            stop = size if before is None else min(before, size)
            start = max(0, stop - LOG_PAGE_BYTES)
            content = os.pread(source, stop - start, start)
            if start and os.pread(source, 1, start - 1) != b"\n":
                boundary = content.find(b"\n") + 1
                if 0 < boundary < len(content):
                    start += boundary
                    content = content[boundary:]
    return LogPage(
        content.decode("utf-8", errors="replace"), start, start + len(content), size
    )


class PlumLogsView(BaseView):
    """Display log files from the configured directory for the Admin role."""

    route_base = "/plumlogs"
    default_view = "index"
    base_permissions = ["can_index"]

    @expose("/")
    @has_access
    def index(self):
        """Render the chosen file, starting at its tail on the first request."""
        if not self.appbuilder.sm.is_plum_admin():
            abort(403)
        selected = request.args.get("file")
        before, after = _offset("before"), _offset("after")
        if before == 0 or (before is not None and after is not None):
            abort(400)

        files, page, error, status = [], None, None, 200
        log_dir = configured_log_directory(current_app.config)
        try:
            with _open_descriptor(log_dir, os.O_DIRECTORY) as directory:
                files = _list_logs(directory)
                if selected is not None and selected not in files:
                    abort(404)
                selected = selected or next(iter(files), None)
                if selected:
                    page = _read_log_page(directory, selected, before, after)
        except FileNotFoundError:
            if selected is not None:
                abort(404)
        except OSError:
            error, status = "Logs are temporarily unavailable.", 503

        response = make_response(
            self.render_template(
                "plum_logs.html",
                log_dir=log_dir,
                files=files,
                selected=selected,
                page=page,
                error=error,
            ),
            status,
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "same-origin"
        return response
