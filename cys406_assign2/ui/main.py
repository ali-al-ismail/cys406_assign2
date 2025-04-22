"""Main for UI."""

import asyncio

import gi

gi.require_version("Adw", "1")
from gi.repository import Adw, GLib

from .main_window import MainWindow


class Cys406Assign2(Adw.Application):
    """Main class for the application."""

    def __init__(self) -> None:
        super().__init__(
            application_id="com.github.cys406assign2",
        )
        GLib.set_application_name("CYS406 Assign 2")

    def do_activate(self) -> None:
        """Activate the application."""
        Adw.Application.do_activate(self)
        self.window = self.props.active_window

        if not self.window:
            self.window = MainWindow(self)

        self.window.present()


def ui():
    """Launch function for the UI."""
    app = Cys406Assign2()
    app.run(None)