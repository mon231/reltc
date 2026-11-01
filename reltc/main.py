import re
import sys
import ipaddress
from typing import List, Optional
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QComboBox, QLineEdit, QPushButton, QGroupBox, QLabel,
    QCheckBox, QTextEdit, QGridLayout
)
from PyQt5.QtGui import QFont

class TCCommandGenerator:
    MODE_FLOWER = "flower"
    MODE_U32 = "u32"
    MODE_IPTABLES = "iptables"

    # a ranged action can't be done by a single pedit rule, so it is expanded to one filter per port
    MAX_FILTERS = 1024

    # header offsets, relative to the start of the ip header (assumes no ip options)
    IP_PROTO_OFFSET = 9
    IP_SRC_OFFSET = 12
    IP_DST_OFFSET = 16
    # the "evil bit" (RFC 3514) is the reserved top bit of the ip flags / fragment-offset field
    IP_FLAGS_OFFSET = 6
    EVIL_BIT = "0x8000"
    L4_SPORT_OFFSET = 20
    L4_DPORT_OFFSET = 22

    @staticmethod
    def is_ip_address(ip_address: str) -> bool:
        try:
            ipaddress.IPv4Address(ip_address)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_any_ip(ip_address: str) -> bool:
        return ip_address in ("", "0.0.0.0", "0.0.0.0/0")

    @staticmethod
    def is_port(port: str) -> bool:
        try:
            port_val = int(port)
            return 0 < port_val <= 65535
        except ValueError:
            return False

    @staticmethod
    def parse_port_range(ports: str):
        """Returns (low, high) for 'N' or 'N-M', or None if invalid."""
        low, sep, high = ports.partition("-")
        if not TCCommandGenerator.is_port(low):
            return None

        if not sep:
            return int(low), int(low)

        if not TCCommandGenerator.is_port(high) or int(high) < int(low):
            return None

        return int(low), int(high)

    @staticmethod
    def is_any_port(ports: str) -> bool:
        return ports == "" or TCCommandGenerator.parse_port_range(ports) == (1, 65535)

    @staticmethod
    def port_variants(config, key: str):
        """
        Returns the (filter_port, patch_port) pairs to emit one filter for, for the 'src' / 'dst' port.
        None means "no match" / "no patch".
        """
        gen = TCCommandGenerator
        if config['protocol'] not in ['tcp', 'udp']:
            return [(None, None)]

        filter_text = config[f'{key}_port']
        patch_text = "" if config['drop_packet'] else config[f'patch_{key}_port']

        filter_range = None if gen.is_any_port(filter_text) else gen.parse_port_range(filter_text)
        patch_range = gen.parse_port_range(patch_text) if patch_text else None
        patch_port = str(patch_range[0]) if patch_range else None
        patch_is_range = patch_range is not None and patch_range[1] > patch_range[0]

        if filter_range is None and patch_is_range:
            filter_range = (1, 65535)

        if filter_range is None:
            return [(None, patch_port)]

        low, high = filter_range
        if patch_is_range:
            # map the n-th filter port to the n-th patch port
            return [(str(low + i), str(patch_range[0] + i)) for i in range(high - low + 1)]

        if config['mode'] == gen.MODE_U32 and high > low:
            # u32 has no ranges
            return [(str(port), patch_port) for port in range(low, high + 1)]

        return [(f"{low}-{high}" if high > low else str(low), patch_port)]

    @staticmethod
    def validate_iptables_action(config) -> Optional[str]:
        """iptables can only rewrite the destination on ingress (DNAT) / the source on egress (SNAT)."""
        if config['patch_evil_bit']:
            return "iptables can't set the evil bit, use a tc mode for that."

        if config['continue_filtering']:
            return "iptables can't 'continue filtering': NAT targets always end the chain."

        if config['direction'] == 'ingress':
            if config['patch_src_ip'] or config['patch_src_port']:
                return "iptables can only rewrite the destination on ingress (DNAT). Clear the source action fields."
        elif config['patch_dst_ip'] or config['patch_dst_port']:
            return "iptables can only rewrite the source on egress (SNAT). Clear the destination action fields."

        return None

    @staticmethod
    def validate(config) -> Optional[str]:
        """Returns an error message if the config can't be turned into commands, otherwise None."""
        gen = TCCommandGenerator
        has_ports = config['protocol'] in ['tcp', 'udp']
        drop = config['drop_packet']

        if not re.fullmatch(r"[^\s/:]{1,15}", config['interface']):
            return "Invalid interface name (1-15 characters, no spaces, '/' or ':')."

        for label, key in (("source", "src_ip"), ("destination", "dst_ip")):
            ip = config[key]
            if not gen.is_any_ip(ip) and not gen.is_ip_address(ip):
                return f"Invalid {label} IP address (e.g. 1.1.1.1, empty = all)."

        if has_ports:
            for label, key in (("source", "src"), ("destination", "dst")):
                filter_text = config[f'{key}_port']
                if not gen.is_any_port(filter_text):
                    filter_range = gen.parse_port_range(filter_text)
                    if filter_range is None:
                        return f"Invalid {label} port filter (use N or N-M, within 1-65535, empty = all)."
                else:
                    filter_range = (1, 65535)

                patch_text = config[f'patch_{key}_port']
                if drop or not patch_text:
                    continue

                patch_range = gen.parse_port_range(patch_text)
                if patch_range is None:
                    return f"Invalid {label} port action (use N or N-M, within 1-65535, empty = leave as in filter)."

                filter_size = filter_range[1] - filter_range[0] + 1
                patch_size = patch_range[1] - patch_range[0] + 1
                if patch_size > 1 and patch_size != filter_size:
                    return (f"The {label} port action range ({patch_size} ports) must be the same size "
                            f"as the {label} port filter range ({filter_size} ports), or a single port.")

        if config['evil_bit'] and config['mode'] == gen.MODE_FLOWER:
            return "Matching on the evil bit is not possible in flower mode (use 'offsets/bits' or iptables)."

        if not drop:
            for label, key in (("source", "patch_src_ip"), ("destination", "patch_dst_ip")):
                ip = config[key]
                if ip and not gen.is_ip_address(ip):
                    return f"Invalid {label} IP action (e.g. 2.2.2.2, empty = leave as in filter)."

            patch_keys = ['patch_src_ip', 'patch_dst_ip'] + (['patch_src_port', 'patch_dst_port'] if has_ports else [])
            if not config['patch_evil_bit'] and not any(config[key] for key in patch_keys):
                return "The action patches nothing: fill at least one action field, or select 'Drop packet'."

        if config['mode'] == gen.MODE_IPTABLES and not drop:
            error = gen.validate_iptables_action(config)
            if error:
                return error

        count = len(gen.port_variants(config, 'src')) * len(gen.port_variants(config, 'dst'))
        if count > gen.MAX_FILTERS:
            return (f"This would generate {count} filters (max {gen.MAX_FILTERS}). "
                    f"Use a smaller port range" + (" or flower mode." if config['mode'] == gen.MODE_U32 else "."))

        return None

    @staticmethod
    def count_rules(commands: List[str]) -> int:
        """The number of generated rules (everything but the one-time qdisc setup)."""
        return len([command for command in commands if not command.startswith("tc qdisc")])

    @staticmethod
    def generate_iptables(config) -> List[str]:
        gen = TCCommandGenerator
        ingress = config['direction'] == 'ingress'
        chain = 'PREROUTING' if ingress else 'POSTROUTING'
        insert = f"-I {chain} 1" if config['priority'] else f"-A {chain}"

        commands = []
        for src_port, patch_src_port in gen.port_variants(config, 'src'):
            for dst_port, patch_dst_port in gen.port_variants(config, 'dst'):
                rule = f"{'-i' if ingress else '-o'} {config['interface']} -p {config['protocol']}"

                for flag, key in (('-s', 'src_ip'), ('-d', 'dst_ip')):
                    if not gen.is_any_ip(config[key]):
                        rule += f" {flag} {config[key]}"

                for flag, port in (('--sport', src_port), ('--dport', dst_port)):
                    if port is not None:
                        rule += f" {flag} {port.replace('-', ':')}"

                if config['evil_bit']:
                    # the 32 bits at offset 4 hold the ip id (high 16) and the flags / fragment offset (low 16)
                    rule += ' -m u32 --u32 "4&0x8000=0x8000"'

                if config['drop_packet']:
                    table, target = 'mangle', '-j DROP'
                elif ingress:
                    to = config['patch_dst_ip'] + (f":{patch_dst_port}" if patch_dst_port else "")
                    table, target = 'nat', f'-j DNAT --to-destination {to}'
                else:
                    to = config['patch_src_ip'] + (f":{patch_src_port}" if patch_src_port else "")
                    table, target = 'nat', f'-j SNAT --to-source {to}'

                commands.append(f"iptables -t {table} {insert} {rule} {target};")

        return commands

    @staticmethod
    def generate_commands(config) -> List[str]:
        gen = TCCommandGenerator
        if config['mode'] == gen.MODE_IPTABLES:
            return gen.generate_iptables(config)

        u32 = config['mode'] == gen.MODE_U32
        has_ports = config['protocol'] in ['tcp', 'udp']
        proto_num = 6 if config['protocol'] == 'tcp' else 17

        commands = [f"tc qdisc add dev {config['interface']} clsact;"]

        for src_port, patch_src_port in gen.port_variants(config, 'src'):
            for dst_port, patch_dst_port in gen.port_variants(config, 'dst'):
                ports = {'src_port': src_port, 'dst_port': dst_port}
                patch_ports = {'src_port': patch_src_port, 'dst_port': patch_dst_port}

                filter_cmd = f"tc filter add dev {config['interface']} {config['direction']} protocol ip"

                if config['priority']:
                    filter_cmd += f" {config['priority']}"

                # filters: an empty (or catch-all) field means "all", so no match is emitted for it
                if u32:
                    filter_cmd += f" u32 match u8 {proto_num} 0xff at {gen.IP_PROTO_OFFSET}"
                else:
                    filter_cmd += f" flower ip_proto {config['protocol']}"

                for name, offset in (('src', gen.IP_SRC_OFFSET), ('dst', gen.IP_DST_OFFSET)):
                    ip = config[f'{name}_ip']
                    if gen.is_any_ip(ip):
                        continue

                    if u32:
                        filter_cmd += f" match u32 0x{int(ipaddress.IPv4Address(ip)):08x} 0xffffffff at {offset}"
                    else:
                        filter_cmd += f" {name}_ip {ip}"

                if config['evil_bit']:
                    filter_cmd += f" match u16 {gen.EVIL_BIT} {gen.EVIL_BIT} at {gen.IP_FLAGS_OFFSET}"

                for name, offset in (('src', 0), ('dst', 2)):
                    port = ports[f'{name}_port']
                    if port is None:
                        continue

                    if u32:
                        filter_cmd += f" match u16 {port} 0xffff at nexthdr+{offset}"
                    else:
                        filter_cmd += f" {name}_port {port}"

                # actions: an empty field means "leave as in filter", so nothing is patched for it
                patches = []
                if not config['drop_packet']:
                    if u32:
                        fields = (('src_ip', gen.IP_SRC_OFFSET, 'u32'), ('dst_ip', gen.IP_DST_OFFSET, 'u32'),
                                  ('src_port', gen.L4_SPORT_OFFSET, 'u16'), ('dst_port', gen.L4_DPORT_OFFSET, 'u16'))
                    else:
                        fields = (('src_ip', 'ip src', None), ('dst_ip', 'ip dst', None),
                                  ('src_port', f"{config['protocol']} sport", None),
                                  ('dst_port', f"{config['protocol']} dport", None))

                    for name, where, kind in fields:
                        value = patch_ports[name] if name.endswith('port') else config[f'patch_{name}']
                        if not value or (not has_ports and name.endswith('port')):
                            continue

                        if u32:
                            if name.endswith('ip'):
                                value = f"0x{int(ipaddress.IPv4Address(value)):08x}"
                            patches.append(f"munge offset {where} {kind} set {value}")
                        else:
                            patches.append(f"munge {where} set {value}")

                    if config['patch_evil_bit']:
                        patches.append(f"munge offset {gen.IP_FLAGS_OFFSET} u16 set {gen.EVIL_BIT} retain {gen.EVIL_BIT}")

                if config['drop_packet']:
                    filter_cmd += " action drop"
                elif patches:
                    filter_cmd += " action pedit ex " + " ".join(patches)
                    filter_cmd += " continue" if config['continue_filtering'] else " pipe"

                commands.append(f'{filter_cmd};')

        return commands


class RelTC(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    @staticmethod
    def make_input(placeholder, width):
        line_edit = QLineEdit()
        line_edit.setPlaceholderText(placeholder)
        line_edit.setMinimumWidth(width)
        line_edit.setClearButtonEnabled(True)
        return line_edit

    def make_grid_group(self, title, hint, ip_placeholder, port_placeholder, evil_text):
        """Builds a 'source / destination' x 'ip / port' grid, returns (group, src_ip, src_port, dst_ip, dst_port, evil_check)."""
        group = QGroupBox(title)
        group.setToolTip(hint)
        grid = QGridLayout()
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(2, 1)

        grid.addWidget(QLabel("IP"), 0, 1)
        grid.addWidget(QLabel("Port / port range"), 0, 2)

        inputs = []
        for row, side in enumerate(("source", "destination"), start=1):
            grid.addWidget(QLabel(f"{side}:"), row, 0)
            ip_input = self.make_input(ip_placeholder, 140)
            port_input = self.make_input(port_placeholder, 160)
            grid.addWidget(ip_input, row, 1)
            grid.addWidget(port_input, row, 2)
            inputs += [ip_input, port_input]

        evil_check = QCheckBox(evil_text)
        evil_check.setToolTip("The reserved top bit of the IPv4 flags field (RFC 3514)")
        grid.addWidget(evil_check, 3, 0, 1, 3)

        group.setLayout(grid)
        return (group, *inputs, evil_check)

    def initUI(self):
        self.setWindowTitle('RelTC - TC Command Generator')

        central_widget = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setSpacing(10)

        # Interface / direction / protocol / match-mode, on a single grid
        setup_group = QGroupBox("Setup")
        setup_layout = QGridLayout()

        self.interface_input = QLineEdit("eth0")
        self.interface_input.setMaxLength(15)
        self.interface_input.setToolTip("Network interface name (1-15 characters)")

        self.direction_combo = QComboBox()
        self.direction_combo.addItems(["ingress", "egress"])

        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["tcp", "udp"])

        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["flower", "offsets/bits", "iptables"])
        self.mode_combo.setToolTip("flower: named fields.\nu32: raw header offsets and bit masks (no port ranges, "
                                   "ranges are expanded to one filter per port).\n"
                                   "iptables: generates iptables rules instead of tc ones "
                                   "(ingress rewrites the destination, egress rewrites the source).")

        for column, (label, widget) in enumerate((("interface", self.interface_input),
                                                  ("direction", self.direction_combo),
                                                  ("protocol", self.protocol_combo),
                                                  ("match by", self.mode_combo))):
            setup_layout.addWidget(QLabel(label), 0, column)
            setup_layout.addWidget(widget, 1, column)

        setup_group.setLayout(setup_layout)
        main_layout.addWidget(setup_group)

        # Filter: empty = all
        (filters_group, self.src_ip_input, self.src_port_input,
         self.dst_ip_input, self.dst_port_input, self.evil_check) = self.make_grid_group(
            "Filter  (empty = all)", "Packets matching ALL of the filled fields are handled by the action",
            "any", "any  (80, 1000-2000)", "Only packets with the evil bit set (not in flower mode)")
        main_layout.addWidget(filters_group)

        # Action: empty = leave as in filter
        (patch_group, self.patch_src_ip_input, self.patch_src_port_input,
         self.patch_dst_ip_input, self.patch_dst_port_input, self.patch_evil_check) = self.make_grid_group(
            "Action: patch fields  (empty = leave as in filter)",
            "A port range here must be the same size as the filter's port range (or be a single port)",
            "unchanged", "unchanged  (same size as filter)", "Set the evil bit (tc only)")
        self.patch_group = patch_group
        main_layout.addWidget(patch_group)

        # Additional options
        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout()

        self.drop_check = QCheckBox("Drop packet (instead of patching)")
        self.continue_check = QCheckBox("Continue filtering (don't stop at this filter)")
        self.prioritized_check = QCheckBox("Make this filter prioritized (pref 1)")
        for check in (self.drop_check, self.continue_check, self.prioritized_check):
            options_layout.addWidget(check)

        options_group.setLayout(options_layout)
        main_layout.addWidget(options_group)

        # Output
        command_group = QGroupBox("Generated Commands")
        command_layout = QVBoxLayout()

        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        command_layout.addWidget(self.status_label)

        self.command_output = QTextEdit()
        self.command_output.setReadOnly(True)
        self.command_output.setLineWrapMode(QTextEdit.NoWrap)
        self.command_output.setFont(QFont("Courier New", 10))
        self.command_output.setMinimumHeight(110)
        command_layout.addWidget(self.command_output)

        buttons_layout = QHBoxLayout()
        self.swap_button = QPushButton("Swap filter / patch")
        self.swap_button.setToolTip("Swaps filter source <-> action destination and filter destination <-> action source")
        self.swap_button.clicked.connect(self.swap_patch_filter)
        buttons_layout.addWidget(self.swap_button)

        self.copy_button = QPushButton("Copy commands")
        self.copy_button.clicked.connect(self.generate_and_copy)
        buttons_layout.addWidget(self.copy_button)
        command_layout.addLayout(buttons_layout)

        command_group.setLayout(command_layout)
        main_layout.addWidget(command_group, stretch=1)

        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        # Commands are generated live, on every change
        for line_edit in (self.interface_input, self.src_ip_input, self.src_port_input, self.dst_ip_input,
                          self.dst_port_input, self.patch_src_ip_input, self.patch_src_port_input,
                          self.patch_dst_ip_input, self.patch_dst_port_input):
            line_edit.textChanged.connect(self.refresh)

        for combo in (self.direction_combo, self.protocol_combo, self.mode_combo):
            combo.currentIndexChanged.connect(self.refresh)

        for check in (self.continue_check, self.prioritized_check, self.evil_check, self.patch_evil_check):
            check.toggled.connect(self.refresh)

        self.protocol_combo.currentTextChanged.connect(self.on_protocol_changed)
        self.drop_check.toggled.connect(self.on_drop_toggled)

        self.on_protocol_changed(self.protocol_combo.currentText())
        self.refresh()

    def on_protocol_changed(self, protocol):
        """Enable or disable port fields based on protocol selection."""
        enable_ports = protocol in ["tcp", "udp"]
        enable_patch_ports = enable_ports and not self.drop_check.isChecked()
        self.src_port_input.setEnabled(enable_ports)
        self.dst_port_input.setEnabled(enable_ports)
        self.patch_src_port_input.setEnabled(enable_patch_ports)
        self.patch_dst_port_input.setEnabled(enable_patch_ports)

    def on_drop_toggled(self, checked):
        """Enable or disable patch fields based on drop packet selection."""
        self.patch_group.setEnabled(not checked)
        self.continue_check.setEnabled(not checked)

        if checked:
            self.continue_check.setChecked(False)

    def read_config(self):
        return {
            'mode': (TCCommandGenerator.MODE_FLOWER, TCCommandGenerator.MODE_U32,
                     TCCommandGenerator.MODE_IPTABLES)[self.mode_combo.currentIndex()],
            'interface': self.interface_input.text().strip(),
            'direction': self.direction_combo.currentText(),
            'protocol': self.protocol_combo.currentText(),
            'src_ip': self.src_ip_input.text().strip(),
            'dst_ip': self.dst_ip_input.text().strip(),
            'src_port': self.src_port_input.text().strip(),
            'dst_port': self.dst_port_input.text().strip(),
            'priority': "pref 1" if self.prioritized_check.isChecked() else "",
            'patch_src_ip': self.patch_src_ip_input.text().strip(),
            'patch_dst_ip': self.patch_dst_ip_input.text().strip(),
            'patch_src_port': self.patch_src_port_input.text().strip(),
            'patch_dst_port': self.patch_dst_port_input.text().strip(),
            'continue_filtering': self.continue_check.isChecked(),
            'drop_packet': self.drop_check.isChecked(),
            'evil_bit': self.evil_check.isChecked(),
            'patch_evil_bit': self.patch_evil_check.isChecked()
        }

    def refresh(self, *_):
        """Validates the inputs and regenerates the commands. Returns True if the inputs are valid."""
        config = self.read_config()
        error = TCCommandGenerator.validate(config)

        self.copy_button.setEnabled(error is None)
        if error:
            self.command_output.clear()
            self.status_label.setStyleSheet("color: #d32f2f;")
            self.status_label.setText(f"✖ {error}")
            return False

        commands = TCCommandGenerator.generate_commands(config)
        self.command_output.setPlainText("\n".join(commands))

        filters_count = TCCommandGenerator.count_rules(commands)
        status = f"✔ Valid: {filters_count} filter{'s' if filters_count != 1 else ''}"

        self.status_label.setStyleSheet("color: #388e3c;")
        self.status_label.setText(status)
        return True

    def swap_patch_filter(self):
        """Swap filter and patch values: filter src <-> patch dst, filter dst <-> patch src."""
        if self.drop_check.isChecked():
            self.status_label.setStyleSheet("color: #d32f2f;")
            self.status_label.setText("✖ Nothing to swap: 'Drop packet' has no patch fields.")
            return

        if not self.refresh():
            return

        pairs = (
            (self.src_ip_input, self.patch_dst_ip_input),
            (self.src_port_input, self.patch_dst_port_input),
            (self.dst_ip_input, self.patch_src_ip_input),
            (self.dst_port_input, self.patch_src_port_input),
        )
        for filter_input, patch_input in pairs:
            filter_text, patch_text = filter_input.text().strip(), patch_input.text().strip()
            filter_input.setText(patch_text)
            patch_input.setText(filter_text)

    def generate_and_copy(self):
        if not self.refresh():
            return

        QApplication.clipboard().setText(self.command_output.toPlainText())
        self.status_label.setStyleSheet("color: #388e3c;")
        self.status_label.setText("✔ Commands copied to clipboard")


def main():
    app = QApplication(sys.argv)
    gui = RelTC()

    gui.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
