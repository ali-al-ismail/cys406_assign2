"""RSA view."""

###
# structure:
# - textview for input
# - space with buttons for encrypt / decrypt / sign / verify
# - textview for output
###

from base64 import b64decode, b64encode
from binascii import Error as binasciiError
from typing import TYPE_CHECKING

import gi

if TYPE_CHECKING:
    from cys406_assign2.ui.main_window import MainWindow

from cys406_assign2.crypto.rsa import (
    RSA,
    MessageTooLongError,
    PrivateKey,
    PrivateKeyError,
    PublicKey,
    PublicKeyError,
)

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk


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

        self.confirm_button = Gtk.Button(
            label="Generate", css_classes=["suggested-action"])
        header.pack_end(self.confirm_button)

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

    def get_prime_size(self) -> int:
        """Get the prime size."""
        return int(self._prime_size.get_value())


class VerifyDialog(Adw.Dialog):
    """Dialog for verifying a signature."""

    def __init__(self) -> None:
        """Initialize verify dialog."""
        super().__init__()
        layout = Adw.ToolbarView()
        self.set_child(layout)

        header = Adw.HeaderBar()
        header.set_show_end_title_buttons(False)
        layout.add_bottom_bar(header)

        cancel_button = Gtk.Button(label="Cancel", css_classes=["destructive-action"])
        cancel_button.connect("clicked", lambda _: self.close())
        header.pack_start(cancel_button)

        self.confirm_button = Gtk.Button(
            label="Verify", css_classes=["suggested-action"])
        header.pack_end(self.confirm_button)

        content = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=15,
            margin_start=6,
            margin_end=6,
            margin_top=6,
            margin_bottom=6,

        )

        self._signature = Gtk.TextView(wrap_mode=Gtk.WrapMode.CHAR, vexpand=True)
        self._message = Gtk.TextView(wrap_mode=Gtk.WrapMode.CHAR, vexpand=True)

        content.append(Gtk.Frame(
            child=Gtk.ScrolledWindow(child=self._signature),
            label="Signature",
        ))
        content.append(Gtk.Frame(
            child=Gtk.ScrolledWindow(child=self._message),
            label="Message",
        ))
        layout.set_content(content)

    def get_signature(self) -> str:
        """Get the signature."""
        start = self._signature.get_buffer().get_start_iter()
        end = self._signature.get_buffer().get_end_iter()
        return self._signature.get_buffer().get_text(
            start, end, include_hidden_chars=False)
    def get_message(self) -> str:
        """Get the message."""
        start = self._message.get_buffer().get_start_iter()
        end = self._message.get_buffer().get_end_iter()
        return self._message.get_buffer().get_text(
            start, end, include_hidden_chars=False)





class RSAView(Adw.Bin):
    """RSA View."""

    def __init__(self, window: "MainWindow") -> None:  # noqa: PLR0915
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
        self.split_view.set_size_request(300, 0)

        # keygen button
        self.keygen_button = Gtk.Button(label="Generate Key Pair")
        self.keygen_button.set_vexpand(False)
        self.keygen_button.set_hexpand(False)
        self.keygen_button.set_margin_top(8)
        self.keygen_button.set_margin_bottom(2)
        self.keygen_button.set_margin_start(8)
        self.keygen_button.set_margin_end(8)
        self.keygen_button.set_valign(Gtk.Align.START)
        self.keygen_button.set_halign(Gtk.Align.CENTER)
        self.keygen_button.set_tooltip_text("Generate a new RSA key pair")
        self.keygen_button.connect("clicked", self._on_keygen_clicked)
        sidebar_box.append(self.keygen_button)

        # expander row for public key
        public_key_expander = Adw.ExpanderRow(title="Public Key",
            height_request=250)
        self.pke = Gtk.TextView(wrap_mode=Gtk.WrapMode.CHAR, vexpand=True)
        self.pkn = Gtk.TextView(wrap_mode=Gtk.WrapMode.CHAR, vexpand=True)
        public_key_expander.add_row(
            Gtk.Frame(
                child=Gtk.ScrolledWindow(child=self.pke),
                label="e",
                margin_bottom=15
            )
        )
        public_key_expander.add_row(
            Gtk.Frame(
                child=Gtk.ScrolledWindow(child=self.pkn),
                label="n",
                margin_bottom=15
            )
        )
        sidebar_box.append(public_key_expander)

        # expander row for private key
        private_key_expander = Adw.ExpanderRow(title="Private Key")
        self.prvn = Gtk.TextView(wrap_mode=Gtk.WrapMode.CHAR, vexpand=True)
        self.prvd = Gtk.TextView(wrap_mode=Gtk.WrapMode.CHAR, vexpand=True)
        private_key_expander.add_row(
            Gtk.Frame(
                child=Gtk.ScrolledWindow(child=self.prvd),
                label="d",
                margin_bottom=15
            )
        )
        private_key_expander.add_row(
            Gtk.Frame(
                child=Gtk.ScrolledWindow(child=self.prvn),
                label="n",
                margin_bottom=15
            )
        )
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
        encrypt_button.connect("clicked", self._encrypt)
        button_box.append(encrypt_button)

        decrypt_button = Gtk.Button(label="Decrypt")
        decrypt_button.connect("clicked", self._decrypt)
        button_box.append(decrypt_button)

        sign_button = Gtk.Button(label="Sign")
        sign_button.connect("clicked", self._sign)
        button_box.append(sign_button)

        verify_button = Gtk.Button(label="Verify")
        verify_button.connect("clicked", self._on_verify_clicked)
        button_box.append(verify_button)

        # output field
        self._output = Gtk.TextView(wrap_mode=Gtk.WrapMode.CHAR, vexpand=True)
        self._output.set_editable(False)
        main_box.append(Gtk.Frame(
            child=Gtk.ScrolledWindow(child=self._output),
            label="Output"))




        # set main box as content
        self.split_view.set_content(main_box)




    def _on_keygen_clicked(self, _button: Gtk.Button) -> None:
        """Generate a new RSA key pair."""
        dialog = KeyDialog()
        def on_generate(_button: Gtk.Button) -> None:
            """Generate keys."""
            prime_size = dialog.get_prime_size()
            public_key, private_key = RSA.generate_keys(prime_size)
            self.pke.get_buffer().set_text(str(public_key.e))
            self.pkn.get_buffer().set_text(str(public_key.n))
            self.prvn.get_buffer().set_text(str(private_key.n))
            self.prvd.get_buffer().set_text(str(private_key.d))
            dialog.close()
        dialog.confirm_button.connect("clicked", on_generate)
        dialog.present(self.window)

    def _encrypt(self, _button: Gtk.Button) -> None:
        """Encrypt the input text."""
        try:
            public_key = self._get_public_key()
        except PublicKeyError:
            self._show_alert("Invalid public key")
            return
        rsa = RSA(public_key)
        plain_buf = self._input.get_buffer()
        start = plain_buf.get_start_iter()
        end = plain_buf.get_end_iter()
        plaintext = plain_buf.get_text(start, end, include_hidden_chars=False)
        if not plaintext:
            return
        try:
            ciphertext = rsa.encrypt(plaintext.encode())
        except MessageTooLongError:
            self._show_alert("Message is too long for the public key")
            return
        self._output.get_buffer().set_text(b64encode(ciphertext).decode("ascii"))

    def _decrypt(self, _button: Gtk.Button) -> None:
        """Decrypt the input text."""
        try:
            private_key = self._get_private_key()
        except PrivateKeyError:
            self._show_alert("Invalid private key")
            return

        rsa = RSA(private=private_key)
        cipher_buf = self._input.get_buffer()
        start = cipher_buf.get_start_iter()
        end = cipher_buf.get_end_iter()

        try:
            ciphertext = b64decode(cipher_buf.get_text(
                start, end, include_hidden_chars=False).encode())
        except binasciiError:
            return

        if not ciphertext:
            return

        try:
            plaintext = rsa.decrypt(ciphertext)
        except MessageTooLongError:
            self._show_alert("Ciphertext is too long for the private key")
            return

        try:
            self._output.get_buffer().set_text(plaintext.decode("ascii"))
        except UnicodeDecodeError:
            self._output.get_buffer().set_text("Decryption failed: invalid ciphertext")
            return

    def _sign(self, _button: Gtk.Button) -> None:
        """Sign the input text."""
        try:
            private_key = self._get_private_key()
        except PrivateKeyError:
            self._show_alert("Invalid private key")
            return
        rsa = RSA(private=private_key)
        plain_buf = self._input.get_buffer()
        start = plain_buf.get_start_iter()
        end = plain_buf.get_end_iter()
        plaintext = plain_buf.get_text(start, end, include_hidden_chars=False)
        if not plaintext:
            return
        signature = rsa.sign(plaintext.encode())
        self._output.get_buffer().set_text(b64encode(signature).decode("ascii"))

    def _on_verify_clicked(self, _button: Gtk.Button) -> None:
        """Show verify dialog."""
        dialog = VerifyDialog()

        def on_verify(_button: Gtk.Button) -> None:
            """Verify the signature."""
            try:
                public_key = self._get_public_key()
            except PublicKeyError:
                self._show_alert("Invalid public key")
                return
            rsa = RSA(public=public_key)
            signature = b64decode(dialog.get_signature().encode())
            message = dialog.get_message().encode()
            if not signature or not message:
                return
            result = rsa.verify(message, signature)
            if result:
                self._output.get_buffer().set_text("Signature is valid")
            else:
                self._output.get_buffer().set_text("Signature is invalid")
            dialog.close()
        dialog.confirm_button.connect("clicked", on_verify)
        dialog.present(self.window)

    def _get_public_key(self) -> PublicKey:
        """Get the public key."""
        n_buf = self.pkn.get_buffer()
        e_buf = self.pke.get_buffer()
        start = n_buf.get_start_iter()
        end = n_buf.get_end_iter()
        try:
            n = int(n_buf.get_text(start, end, include_hidden_chars=False))
            start = e_buf.get_start_iter()
            end = e_buf.get_end_iter()
            e = int(e_buf.get_text(start, end, include_hidden_chars=False))
            return PublicKey(n, e)
        except ValueError as e:
            raise PublicKeyError from e

    def _get_private_key(self) -> PrivateKey:
        """Get the private key."""
        n_buf = self.prvn.get_buffer()
        d_buf = self.prvd.get_buffer()
        start = n_buf.get_start_iter()
        end = n_buf.get_end_iter()
        try:
            n = int(n_buf.get_text(start, end, include_hidden_chars=False))
            start = d_buf.get_start_iter()
            end = d_buf.get_end_iter()
            d = int(d_buf.get_text(start, end, include_hidden_chars=False))
            return PrivateKey(n, d)
        except ValueError as e:
            raise PrivateKeyError from e

    def _show_alert(self, message: str) -> None:
        """Show an alert dialog."""
        dialog = Adw.AlertDialog(
            title="Error",
            body=message,
        )
        dialog.add_response(
            "OK",
            label="OK",
        )
        dialog.set_response_appearance("OK", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.present(self.window)
