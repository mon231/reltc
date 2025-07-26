import sys
import ipaddress
from typing import List, Optional
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QComboBox, QLineEdit, QPushButton, QGroupBox,
    QCheckBox, QTextEdit, QTabWidget, QFormLayout, QMessageBox
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

class TCCommandGenerator:
    @staticmethod
    def is_ip_address(ip_address: str) -> bool:
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_port(port: str) -> bool:
        try:
            port_val = int(port)
            return (port_val > 0) and (port_val < 65535)
        except ValueError:
            return False

    @staticmethod
    def generate_ip_match(field: str, ip_address: Optional[str]) -> str:
        if not ip_address:
            return ""

        return f"{field} {ip_address}"

    @staticmethod
    def generate_port_match(field: str, port: Optional[str]) -> str:
        if not port:
            return ""

        return f"{field} {port}"

    @staticmethod
    def generate_commands(config) -> List[str]:
        commands = []

        commands.append(f"tc qdisc add dev {config['interface']} clsact;")
        filter_cmd = f"tc filter add dev {config['interface']} {config['direction']} protocol ip"

        if config['priority']:
            filter_cmd += f" {config['priority']}"

        filter_cmd += f" flower ip_proto {config['protocol']}"

        if config['src_ip']:
            filter_cmd += f" src_ip {config['src_ip']}"

        if config['dst_ip']:
            filter_cmd += f" dst_ip {config['dst_ip']}"

        if config['protocol'] in ['tcp', 'udp']:
            if config['src_port']:
                filter_cmd += f" src_port {config['src_port']}"

            if config['dst_port']:
                filter_cmd += f" dst_port {config['dst_port']}"

        if config['drop_packet']:
            filter_cmd += " action drop"
        elif config['patch_fields']:
            # Otherwise, add patching actions if any are selected
            filter_cmd += " action pedit ex"

            # Add patching for each selected field
            for field, value in config['patch_fields'].items():
                if value:
                    if field == 'src_ip' and config['patch_src_ip']:
                        filter_cmd += f" munge ip src set {config['patch_src_ip']}"
                    elif field == 'dst_ip' and config['patch_dst_ip']:
                        filter_cmd += f" munge ip dst set {config['patch_dst_ip']}"
                    elif field == 'src_port' and config['patch_src_port'] and config['protocol'] in ['tcp', 'udp']:
                        filter_cmd += f" munge {config['protocol']} sport set {config['patch_src_port']}"
                    elif field == 'dst_port' and config['patch_dst_port'] and config['protocol'] in ['tcp', 'udp']:
                        filter_cmd += f" munge {config['protocol']} dport set {config['patch_dst_port']}"

        if config['drop_packet']:
            pass
        elif config['continue_filtering']:
            filter_cmd += " continue"
        else:
            filter_cmd += " pipe"

        commands.append(f'{filter_cmd};')
        return commands


class RelTC(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('TC Command Generator')

        central_widget = QWidget()
        main_layout = QVBoxLayout()

        # Create tab widget
        tab_widget = QTabWidget()

        # Create main widget
        main_widget = QWidget()
        filter_layout = QVBoxLayout()

        # Interface and Protocol selection
        interface_protocol_group = QGroupBox("Network Interface / Protocol")
        interface_protocol_layout = QVBoxLayout()
        interface_protocol_layout.setAlignment(Qt.AlignLeft)

        # Interface section
        interface_layout = QFormLayout()
        interface_layout.setFormAlignment(Qt.AlignLeft)
        interface_layout.setLabelAlignment(Qt.AlignLeft)
        self.interface_input = QLineEdit()
        self.interface_input.setText("eth0")
        self.interface_input.setMaximumWidth(80)
        self.interface_input.setMaxLength(10)
        self.interface_input.setLayoutDirection(Qt.LeftToRight)
        interface_layout.addRow("interface:", self.interface_input)
        interface_protocol_layout.addLayout(interface_layout)

        # Direction and Protocol selection (side-by-side)
        dir_proto_layout = QHBoxLayout()

        # Direction section
        direction_layout = QFormLayout()
        direction_layout.setFormAlignment(Qt.AlignLeft)
        direction_layout.setLabelAlignment(Qt.AlignLeft)
        self.direction_combo = QComboBox()
        self.direction_combo.setMaximumWidth(80)
        self.direction_combo.addItems(["ingress", "egress"])
        self.direction_combo.setLayoutDirection(Qt.LeftToRight)
        direction_layout.addRow("direction:", self.direction_combo)
        dir_proto_layout.addLayout(direction_layout)

        # Protocol section
        proto_layout = QFormLayout()
        proto_layout.setFormAlignment(Qt.AlignLeft)
        proto_layout.setLabelAlignment(Qt.AlignLeft)
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["tcp", "udp"])
        self.protocol_combo.setMaximumWidth(50)
        self.protocol_combo.currentTextChanged.connect(self.on_protocol_changed)
        self.protocol_combo.setLayoutDirection(Qt.LeftToRight)
        proto_layout.addRow("protocol:", self.protocol_combo)
        dir_proto_layout.addLayout(proto_layout)

        interface_protocol_layout.addLayout(dir_proto_layout)

        interface_protocol_group.setLayout(interface_protocol_layout)
        filter_layout.addWidget(interface_protocol_group)

        # Filters section (IP and Port)
        filters_group = QGroupBox("Filters")
        filters_layout = QVBoxLayout()
        filters_layout.setAlignment(Qt.AlignLeft)

        # Source IP and Port filters (same line)
        src_filters_layout = QHBoxLayout()

        # Source IP filter
        src_ip_layout = QFormLayout()
        src_ip_layout.setFormAlignment(Qt.AlignLeft)
        src_ip_layout.setLabelAlignment(Qt.AlignLeft)
        self.src_ip_input = QLineEdit()
        self.src_ip_input.setPlaceholderText("e.g. 1.1.1.1")
        self.src_ip_input.setMaximumWidth(200)
        src_ip_layout.addRow("src ip:", self.src_ip_input)
        src_filters_layout.addLayout(src_ip_layout)

        # Source Port filter
        src_port_layout = QFormLayout()
        src_port_layout.setFormAlignment(Qt.AlignLeft)
        src_port_layout.setLabelAlignment(Qt.AlignLeft)
        self.src_port_input = QLineEdit()
        self.src_port_input.setPlaceholderText("e.g. 80")
        self.src_port_input.setMaximumWidth(100)
        src_port_layout.addRow("src port:", self.src_port_input)
        src_filters_layout.addLayout(src_port_layout)

        filters_layout.addLayout(src_filters_layout)

        # Destination IP and Port filters (same line)
        dst_filters_layout = QHBoxLayout()

        # Destination IP filter
        dst_ip_layout = QFormLayout()
        dst_ip_layout.setFormAlignment(Qt.AlignLeft)
        dst_ip_layout.setLabelAlignment(Qt.AlignLeft)
        self.dst_ip_input = QLineEdit()
        self.dst_ip_input.setPlaceholderText("e.g. 3.3.3.3")
        self.dst_ip_input.setMaximumWidth(200)
        dst_ip_layout.addRow("dst ip:", self.dst_ip_input)
        dst_filters_layout.addLayout(dst_ip_layout)

        # Destination Port filter
        dst_port_layout = QFormLayout()
        dst_port_layout.setFormAlignment(Qt.AlignLeft)
        dst_port_layout.setLabelAlignment(Qt.AlignLeft)
        self.dst_port_input = QLineEdit()
        self.dst_port_input.setPlaceholderText("e.g. 443")
        self.dst_port_input.setMaximumWidth(100)
        dst_port_layout.addRow("dst port:", self.dst_port_input)
        dst_filters_layout.addLayout(dst_port_layout)

        filters_layout.addLayout(dst_filters_layout)

        filters_group.setLayout(filters_layout)
        filter_layout.addWidget(filters_group)

        # Store port group reference for enabling/disabling based on protocol
        self.port_group = filters_group

        # Patch fields
        patch_group = QGroupBox("Patch Fields")
        patch_layout = QVBoxLayout()

        # Source IP and Port patch (same line)
        src_patch_layout = QHBoxLayout()

        # Source IP patch
        src_ip_layout = QHBoxLayout()
        self.patch_src_ip_check = QCheckBox("src ip:")
        self.patch_src_ip_input = QLineEdit()
        self.patch_src_ip_input.setEnabled(False)
        self.patch_src_ip_input.setFixedWidth(150)
        self.patch_src_ip_check.toggled.connect(self.patch_src_ip_input.setEnabled)
        src_ip_layout.addWidget(self.patch_src_ip_check)
        src_ip_layout.addWidget(self.patch_src_ip_input)
        src_patch_layout.addLayout(src_ip_layout)

        # Source Port patch
        src_port_layout = QHBoxLayout()
        self.patch_src_port_check = QCheckBox("src port:")
        self.patch_src_port_input = QLineEdit()
        self.patch_src_port_input.setEnabled(False)
        self.patch_src_port_input.setFixedWidth(100)
        self.patch_src_port_check.toggled.connect(self.patch_src_port_input.setEnabled)
        src_port_layout.addWidget(self.patch_src_port_check)
        src_port_layout.addWidget(self.patch_src_port_input)
        src_patch_layout.addLayout(src_port_layout)

        patch_layout.addLayout(src_patch_layout)

        # Destination IP and Port patch (same line)
        dst_patch_layout = QHBoxLayout()

        # Destination IP patch
        dst_ip_layout = QHBoxLayout()
        self.patch_dst_ip_check = QCheckBox("dst ip:")
        self.patch_dst_ip_input = QLineEdit()
        self.patch_dst_ip_input.setEnabled(False)
        self.patch_dst_ip_input.setFixedWidth(150)
        self.patch_dst_ip_check.toggled.connect(self.patch_dst_ip_input.setEnabled)
        dst_ip_layout.addWidget(self.patch_dst_ip_check)
        dst_ip_layout.addWidget(self.patch_dst_ip_input)
        dst_patch_layout.addLayout(dst_ip_layout)

        # Destination Port patch
        dst_port_layout = QHBoxLayout()
        self.patch_dst_port_check = QCheckBox("dst port:")
        self.patch_dst_port_input = QLineEdit()
        self.patch_dst_port_input.setEnabled(False)
        self.patch_dst_port_input.setFixedWidth(100)
        self.patch_dst_port_check.toggled.connect(self.patch_dst_port_input.setEnabled)
        dst_port_layout.addWidget(self.patch_dst_port_check)
        dst_port_layout.addWidget(self.patch_dst_port_input)
        dst_patch_layout.addLayout(dst_port_layout)

        patch_layout.addLayout(dst_patch_layout)

        patch_group.setLayout(patch_layout)
        filter_layout.addWidget(patch_group)

        # Additional options
        options_group = QGroupBox("Additional Options")
        options_layout = QVBoxLayout()
        options_layout.setAlignment(Qt.AlignLeft)

        self.continue_check = QCheckBox("Continue filtering (don't stop at this filter)")
        self.continue_check.setLayoutDirection(Qt.LeftToRight)
        options_layout.addWidget(self.continue_check)

        self.prioritized_check = QCheckBox("Make this filter prioritized (pref 1)")
        self.prioritized_check.setLayoutDirection(Qt.LeftToRight)
        options_layout.addWidget(self.prioritized_check)

        self.drop_check = QCheckBox("Drop packet (instead of patching)")
        self.drop_check.setLayoutDirection(Qt.LeftToRight)
        self.drop_check.toggled.connect(self.on_drop_toggled)
        options_layout.addWidget(self.drop_check)

        options_group.setLayout(options_layout)
        filter_layout.addWidget(options_group)

        # No Generate button - commands are generated automatically

        # Command output section
        command_group = QGroupBox("Generated Commands")
        command_layout = QVBoxLayout()

        swap_button = QPushButton("Swap Filter/Patch")
        swap_button.clicked.connect(self.swap_patch_filter)
        command_layout.addWidget(swap_button)

        copy_button = QPushButton("Generate and Copy")
        copy_button.clicked.connect(self.generate_and_copy)
        command_layout.addWidget(copy_button)

        self.command_output = QTextEdit()
        self.command_output.setReadOnly(True)
        self.command_output.setFont(QFont("Courier New", 10))
        self.command_output.setMinimumHeight(50)
        command_layout.addWidget(self.command_output)

        command_group.setLayout(command_layout)
        filter_layout.addWidget(command_group)

        # Set the layout on the main widget
        main_widget.setLayout(filter_layout)

        # Add main widget to tab widget without a visible tab
        tab_widget.addTab(main_widget, "")
        tab_widget.tabBar().setVisible(False)

        # Add tab widget to main layout
        main_layout.addWidget(tab_widget)

        # Set main layout to central widget
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        # Initialize port fields based on default protocol
        self.on_protocol_changed(self.protocol_combo.currentText())

    def on_protocol_changed(self, protocol):
        """Enable or disable port fields based on protocol selection."""
        enable_ports = protocol in ["tcp", "udp"]
        self.port_group.setEnabled(enable_ports)
        self.patch_src_port_check.setEnabled(enable_ports and not self.drop_check.isChecked())
        self.patch_dst_port_check.setEnabled(enable_ports and not self.drop_check.isChecked())

        # If ports are disabled, uncheck the patch checkboxes
        if not enable_ports:
            self.patch_src_port_check.setChecked(False)
            self.patch_dst_port_check.setChecked(False)

    def on_drop_toggled(self, checked):
        """Enable or disable patch fields based on drop packet selection."""

        enable_patch = not checked
        self.continue_check.setEnabled(enable_patch)

        self.patch_src_ip_check.setEnabled(enable_patch)
        self.patch_dst_ip_check.setEnabled(enable_patch)

        self.patch_src_port_check.setEnabled(enable_patch)
        self.patch_dst_port_check.setEnabled(enable_patch)

        if not enable_patch:
            self.continue_check.setChecked(False)
            self.patch_src_ip_check.setChecked(False)
            self.patch_dst_ip_check.setChecked(False)
            self.patch_src_port_check.setChecked(False)
            self.patch_dst_port_check.setChecked(False)

    def validate_inputs(self):
        """Validate all input fields."""
        # Validate interface
        if not self.interface_input.text().strip():
            QMessageBox.warning(self, "Validation Error", "Interface name is required.")
            return False

        # Validate IP ranges
        src_ip = self.src_ip_input.text().strip()
        dst_ip = self.dst_ip_input.text().strip()

        if src_ip and not TCCommandGenerator.is_ip_address(src_ip):
            QMessageBox.warning(self, "Validation Error", "Invalid source IP address format.")
            return False

        if dst_ip and not TCCommandGenerator.is_ip_address(dst_ip):
            QMessageBox.warning(self, "Validation Error", "Invalid destination IP address format.")
            return False

        # Validate port ranges if protocol is tcp or udp
        if self.protocol_combo.currentText() in ["tcp", "udp"]:
            src_port = self.src_port_input.text().strip()
            dst_port = self.dst_port_input.text().strip()

            if src_port and not TCCommandGenerator.is_port(src_port):
                QMessageBox.warning(self, "Validation Error", "Invalid source port range format.")
                return False

            if dst_port and not TCCommandGenerator.is_port(dst_port):
                QMessageBox.warning(self, "Validation Error", "Invalid destination port range format.")
                return False

        # Validate patch fields
        if self.patch_src_ip_check.isChecked():
            patch_src_ip = self.patch_src_ip_input.text().strip()
            try:
                ipaddress.ip_address(patch_src_ip)
            except ValueError:
                QMessageBox.warning(self, "Validation Error", "Invalid source IP patch value.")
                return False

        if self.patch_dst_ip_check.isChecked():
            patch_dst_ip = self.patch_dst_ip_input.text().strip()
            try:
                ipaddress.ip_address(patch_dst_ip)
            except ValueError:
                QMessageBox.warning(self, "Validation Error", "Invalid destination IP patch value.")
                return False

        if self.patch_src_port_check.isChecked():
            patch_src_port = self.patch_src_port_input.text().strip()
            try:
                port = int(patch_src_port)
                if port < 0 or port > 65535:
                    raise ValueError()
            except ValueError:
                QMessageBox.warning(self, "Validation Error", "Invalid source port patch value.")
                return False

        if self.patch_dst_port_check.isChecked():
            patch_dst_port = self.patch_dst_port_input.text().strip()
            try:
                port = int(patch_dst_port)
                if port < 0 or port > 65535:
                    raise ValueError()
            except ValueError:
                QMessageBox.warning(self, "Validation Error", "Invalid destination port patch value.")
                return False

        return True

    def generate_commands(self):
        if not self.validate_inputs():
            return

        config = {
            'interface': self.interface_input.text().strip(),
            'direction': self.direction_combo.currentText(),
            'protocol': self.protocol_combo.currentText(),
            'src_ip': self.src_ip_input.text().strip(),
            'dst_ip': self.dst_ip_input.text().strip(),
            'src_port': self.src_port_input.text().strip(),
            'dst_port': self.dst_port_input.text().strip(),
            'priority': "pref 1" if self.prioritized_check.isChecked() else "",
            'patch_fields': {
                'src_ip': self.patch_src_ip_check.isChecked(),
                'dst_ip': self.patch_dst_ip_check.isChecked(),
                'src_port': self.patch_src_port_check.isChecked(),
                'dst_port': self.patch_dst_port_check.isChecked()
            },
            'patch_src_ip': self.patch_src_ip_input.text().strip(),
            'patch_dst_ip': self.patch_dst_ip_input.text().strip(),
            'patch_src_port': self.patch_src_port_input.text().strip(),
            'patch_dst_port': self.patch_dst_port_input.text().strip(),
            'continue_filtering': self.continue_check.isChecked(),
            'drop_packet': self.drop_check.isChecked()
        }

        commands = TCCommandGenerator.generate_commands(config)
        self.command_output.setText("\n".join(commands))

    def swap_patch_filter(self):
        # filter src: 1.1.1.1
        # patch dst: 2.2.2.2

        # swap

        # filter src: 2.2.2.2
        # patch dst: 1.1.1.1

        original_filter_src_ip = self.src_ip_input.text().strip()
        original_filter_src_port = self.src_port_input.text().strip()

        original_filter_dst_ip = self.dst_ip_input.text().strip()
        original_filter_dst_port = self.dst_port_input.text().strip()

        original_patch_src_ip = self.patch_src_ip_input.text().strip()
        original_patch_src_port = self.patch_src_port_input.text().strip()

        original_patch_dst_ip = self.patch_dst_ip_input.text().strip()
        original_patch_dst_port = self.patch_dst_port_input.text().strip()

        self.src_ip_input.setText(original_patch_dst_ip)
        self.src_port_input.setText(original_patch_dst_port)

        self.dst_ip_input.setText(original_patch_src_ip)
        self.dst_port_input.setText(original_patch_src_port)

        self.patch_src_ip_input.setText(original_filter_dst_ip)
        self.patch_src_port_input.setText(original_filter_dst_port)

        self.patch_dst_ip_input.setText(original_filter_src_ip)
        self.patch_dst_port_input.setText(original_filter_src_port)

        self.adjust_patch_checkboxes()

    def adjust_patch_checkboxes(self):
        self.patch_src_ip_check.setChecked(self.patch_src_ip_input.text().strip() != '')
        self.patch_src_port_check.setChecked(self.patch_src_port_input.text().strip() != '')

        self.patch_dst_ip_check.setChecked(self.patch_dst_ip_input.text().strip() != '')
        self.patch_dst_port_check.setChecked(self.patch_dst_port_input.text().strip() != '')

        if self.drop_check.isChecked():
            self.patch_src_ip_check.setChecked(False)
            self.patch_dst_ip_check.setChecked(False)
            self.patch_src_port_check.setChecked(False)
            self.patch_dst_port_check.setChecked(False)

    def generate_and_copy(self):
        self.generate_commands()

        clipboard = QApplication.clipboard()
        clipboard.setText(self.command_output.toPlainText())

        if self.drop_check.isChecked():
            QMessageBox.information(self, "Generated & Copied", "Commands were generated & copied")
        else:
            QMessageBox.information(self, "Generated & Copied", "Commands were generated & copied\nNOTE actions other than 'drop' are EXPERIMENTAL only!")


def main():
    app = QApplication(sys.argv)
    gui = RelTC()

    gui.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
