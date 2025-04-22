"""RSA view."""

###
# structure:
# - textview for input
# - space with buttons for encrypt / decrypt / sign / verify
# - textview for output
###

import gi
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cys406_assign2.ui.main_window import MainWindow

from cys406_assign2.crypto.rsa import RSA

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk

class KeyDialog(Adw.Dialog):
    """Dialog for key generation."""

    def __init__(self) -> None:
        """Initialize key generation dialog."""
        super().__init__()
        layout = Adw.ToolbarView()
        self.set_child(layout)

        header = Adw.HeaderBar()
        header.set_show_end_title_buttons(False)
        layout.add_bottom_bar(header)

        cancel_button = Gtk.Button(label="Cancel", css_classes=["destructive-action"])
        cancel_button.connect("clicked", lambda _: self.close())
        header.pack_start(cancel_button)

        confirm_button = Gtk.Button(label="Generate", css_classes=["suggested-action"])
        header.pack_end(confirm_button)

        options = Adw.PreferencesGroup(
            title="RSA Key Generation Options",
            halign= Gtk.Align.FILL,
            margin_end= 30,
            margin_start= 30,
            margin_top= 15,
            margin_bottom= 15,

        )
        layout.set_content(options)

        self._prime_size = Adw.SpinRow.new_with_range(512, 4096, 8)
        self._prime_size.set_title("Prime Size")
        self._prime_size.set_subtitle("Bit size of generated primes")
        self._prime_size.set_value(512)
        options.add(self._prime_size)







class RSAView(Adw.Bin):
    """RSA View."""

    def __init__(self, window: "MainWindow") -> None:
        """Initialize RSA view."""
        super().__init__()
        self.window = window
        self.split_view = Adw.OverlaySplitView()
        self.set_child(self.split_view)

        sidebar_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=6,
            margin_start=6,
            margin_end=6,
            margin_top=6,
            margin_bottom=6,
        )
        self.split_view.set_sidebar(sidebar_box)
        self.split_view.set_size_request(250, 0)

        # keygen button
        self.keygen_button = Gtk.Button(label="Generate Key Pair")
        self.keygen_button.set_vexpand(False)
        self.keygen_button.set_hexpand(False)
        self.keygen_button.set_margin_top(8)
        self.keygen_button.set_margin_bottom(8)
        self.keygen_button.set_margin_start(8)
        self.keygen_button.set_margin_end(8)
        self.keygen_button.set_valign(Gtk.Align.START)
        self.keygen_button.set_halign(Gtk.Align.CENTER)
        self.keygen_button.set_tooltip_text("Generate a new RSA key pair")
        self.keygen_button.connect("clicked", self._on_keygen_clicked)
        sidebar_box.append(self.keygen_button)

        # expander row for public key
        public_key_expander = Adw.ExpanderRow(title="Public Key")
        self.pke = Adw.EntryRow(title = "e")
        self.pkn = Adw.EntryRow(title = "n")
        public_key_expander.add_row(self.pke)
        public_key_expander.add_row(self.pkn)
        sidebar_box.append(public_key_expander)

        # expander row for private key
        private_key_expander = Adw.ExpanderRow(title="Private Key")
        self.prvn = Adw.EntryRow(title = "n")
        self.prvd = Adw.EntryRow(title = "d")
        private_key_expander.add_row(self.prvn)
        private_key_expander.add_row(self.prvd)
        sidebar_box.append(private_key_expander)

        # main box
        main_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=15,
            margin_start=6,
            margin_end=6,
            margin_top=6,
            margin_bottom=6,
        )

        # input field
        self._input = Gtk.TextView(wrap_mode=Gtk.WrapMode.CHAR, vexpand=True)
        main_box.append(Gtk.Frame(
            child=Gtk.ScrolledWindow(child=self._input),
            label="Input"))

        # buttons for encrypt / decrypt / sign / verify
        button_box = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL,
            spacing=25,
            margin_start=8,
            margin_end=8,
        )
        button_box.set_valign(Gtk.Align.CENTER)
        button_box.set_halign(Gtk.Align.CENTER)
        main_box.append(button_box)


        encrypt_button = Gtk.Button(label="Encrypt")
        button_box.append(encrypt_button)
        decrypt_button = Gtk.Button(label="Decrypt")
        button_box.append(decrypt_button)
        sign_button = Gtk.Button(label="Sign")
        button_box.append(sign_button)
        verify_button = Gtk.Button(label="Verify")
        button_box.append(verify_button)

        # output field
        self._output = Gtk.TextView(wrap_mode=Gtk.WrapMode.CHAR, vexpand=True)
        self._output.set_editable(False)
        main_box.append(Gtk.Frame(
            child=Gtk.ScrolledWindow(child=self._output),
            label="Output"))




        # set main box as content
        self.split_view.set_content(main_box)




    def _on_keygen_clicked(self, button: Gtk.Button) -> None:
        """Generate a new RSA key pair."""
        dialog = KeyDialog()
        dialog.present(self.window)