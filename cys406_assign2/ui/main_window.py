""""Main application window."""
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from .rsa_view import RSAView


class MainWindow(Adw.ApplicationWindow):
    """Main window."""

    def __init__(self, application: Adw.Application) -> None:
        """Initialize the main window."""
        super().__init__(application=application, title="CYS406 Assignment 2")
        self.set_size_request(800, 700)

        layout = Adw.ToolbarView()
        self.set_content(layout)

        # header
        header = Adw.HeaderBar()
        header.set_show_title(True)
        layout.add_top_bar(header)

        self._rsa = RSAView(self)
        layout.set_content(self._rsa)




