import ipaddress
import shlex
import unittest
from itertools import product

from reltc.main import TCCommandGenerator as Gen

FLOWER, U32, IPT = Gen.MODE_FLOWER, Gen.MODE_U32, Gen.MODE_IPTABLES


def make_config(**overrides):
    config = {
        'mode': FLOWER,
        'interface': 'eth0',
        'direction': 'ingress',
        'protocol': 'tcp',
        'src_ip': '',
        'dst_ip': '',
        'src_port': '',
        'dst_port': '',
        'priority': '',
        'patch_src_ip': '',
        'patch_dst_ip': '',
        'patch_src_port': '',
        'patch_dst_port': '',
        'continue_filtering': False,
        'drop_packet': False,
        'evil_bit': False,
        'patch_evil_bit': False,
    }
    config.update(overrides)
    return config


def generate(**overrides):
    config = make_config(**overrides)
    error = Gen.validate(config)
    assert error is None, error
    return Gen.generate_commands(config)


# ---- a strict grammar checker for the generated `tc` script ----

class Tokens:
    def __init__(self, tokens):
        self.tokens = list(tokens)

    def peek(self):
        return self.tokens[0] if self.tokens else None

    def next(self):
        assert self.tokens, "unexpected end of command"
        return self.tokens.pop(0)

    def expect(self, *words):
        for word in words:
            got = self.next()
            assert got == word, f"expected {word!r}, got {got!r}"

    def done(self):
        return not self.tokens


def check_port(text, allow_range):
    low, _, high = text.partition('-')
    assert low.isdigit() and 1 <= int(low) <= 65535, text
    if high:
        assert allow_range, f"port range not allowed here: {text}"
        assert high.isdigit() and int(low) < int(high) <= 65535, text


def check_ip(text):
    ipaddress.IPv4Address(text)


def check_hex(text, bits):
    assert text.startswith('0x'), text
    assert 0 <= int(text, 16) < 2 ** bits, text


def parse_script(commands):
    """Validates the structure of the whole script, returns the parsed filters."""
    assert commands, "empty script"
    assert all(command.endswith(';') for command in commands)

    qdisc = Tokens(shlex.split(commands[0][:-1]))
    qdisc.expect('tc', 'qdisc', 'add', 'dev')
    dev = qdisc.next()
    qdisc.expect('clsact')
    assert qdisc.done()

    filters = []
    for command in commands[1:]:
        filters.append(parse_filter(Tokens(shlex.split(command[:-1])), dev))

    assert filters, "script has a qdisc but no filter"
    return filters


def parse_filter(tokens, dev):
    tokens.expect('tc', 'filter', 'add', 'dev', dev)
    assert tokens.next() in ('ingress', 'egress')
    tokens.expect('protocol', 'ip')

    if tokens.peek() == 'pref':
        tokens.expect('pref', '1')

    parsed = {'match': {}, 'patch': {}, 'action': None}
    kind = tokens.next()
    assert kind in ('flower', 'u32'), kind
    parsed['kind'] = kind
    (parse_flower_match if kind == 'flower' else parse_u32_match)(tokens, parsed['match'])

    if tokens.peek() == 'action':
        tokens.next()
        parsed['action'] = tokens.next()
        if parsed['action'] == 'drop':
            assert tokens.done()
        else:
            assert parsed['action'] == 'pedit'
            tokens.expect('ex')
            parse_pedit(tokens, parsed['patch'], kind)
            assert tokens.next() in ('pipe', 'continue')
            assert tokens.done()
    else:
        assert tokens.done()

    return parsed


def parse_flower_match(tokens, match):
    tokens.expect('ip_proto')
    match['proto'] = tokens.next()
    assert match['proto'] in ('tcp', 'udp', 'icmp')

    while tokens.peek() in ('src_ip', 'dst_ip', 'src_port', 'dst_port'):
        name = tokens.next()
        value = tokens.next()
        assert name not in match, f"duplicate {name}"
        if name.endswith('ip'):
            check_ip(value)
        else:
            check_port(value, allow_range=True)
        match[name] = value


def parse_u32_match(tokens, match):
    offsets = {6: 'evil_bit', 9: 'proto', 12: 'src_ip', 16: 'dst_ip'}
    while tokens.peek() == 'match':
        tokens.next()
        size = tokens.next()
        assert size in ('u8', 'u16', 'u32')
        value, mask = tokens.next(), tokens.next()
        tokens.expect('at')
        where = tokens.next()

        if where.startswith('nexthdr+'):
            assert size == 'u16' and mask == '0xffff'
            name = {0: 'src_port', 2: 'dst_port'}[int(where[len('nexthdr+'):])]
            check_port(value, allow_range=False)
        else:
            name = offsets[int(where)]
            if name == 'evil_bit':
                assert (size, value, mask) == ('u16', '0x8000', '0x8000')
            elif name == 'proto':
                assert size == 'u8' and mask == '0xff'
                assert value in ('6', '17')
            else:
                assert size == 'u32' and mask == '0xffffffff'
                check_hex(value, 32)

        assert name not in match, f"duplicate {name}"
        match[name] = value

    assert 'proto' in match, "u32 filter without a protocol match"


def parse_pedit(tokens, patch, kind):
    assert tokens.peek() == 'munge', "pedit without any munge"
    while tokens.peek() == 'munge':
        tokens.next()
        if tokens.peek() == 'offset' and kind == 'flower':
            # the evil bit is a raw pedit, also in flower mode
            tokens.expect('offset', '6', 'u16', 'set', '0x8000', 'retain', '0x8000')
            name, value = 'evil_bit', '0x8000'
        elif kind == 'flower':
            layer, field = tokens.next(), tokens.next()
            name = {('ip', 'src'): 'src_ip', ('ip', 'dst'): 'dst_ip',
                    ('tcp', 'sport'): 'src_port', ('tcp', 'dport'): 'dst_port',
                    ('udp', 'sport'): 'src_port', ('udp', 'dport'): 'dst_port'}[(layer, field)]
            tokens.expect('set')
            value = tokens.next()
            check_ip(value) if name.endswith('ip') else check_port(value, allow_range=False)
        else:
            tokens.expect('offset')
            offset = int(tokens.next())
            size = tokens.next()
            tokens.expect('set')
            value = tokens.next()
            name = {6: 'evil_bit', 12: 'src_ip', 16: 'dst_ip', 20: 'src_port', 22: 'dst_port'}[offset]
            if name == 'evil_bit':
                assert (size, value) == ('u16', '0x8000')
                tokens.expect('retain', '0x8000')
            elif name.endswith('ip'):
                assert size == 'u32'
                check_hex(value, 32)
            else:
                assert size == 'u16'
                check_port(value, allow_range=False)

        assert name not in patch, f"duplicate patch of {name}"
        patch[name] = value


def parse_iptables(commands):
    """Validates the structure of an iptables script, returns the parsed rules."""
    assert commands, "empty script"
    rules = []
    for command in commands:
        assert command.endswith(';')
        tokens = Tokens(shlex.split(command[:-1]))
        tokens.expect('iptables', '-t')
        table = tokens.next()
        assert table in ('mangle', 'nat')

        rule = {'table': table, 'match': {}}
        op = tokens.next()
        assert op in ('-A', '-I')
        rule['chain'] = tokens.next()
        assert rule['chain'] in ('PREROUTING', 'POSTROUTING')
        if op == '-I':
            tokens.expect('1')
        rule['insert'] = op == '-I'

        iface_flag = tokens.next()
        assert iface_flag == ('-i' if rule['chain'] == 'PREROUTING' else '-o')
        rule['iface'] = tokens.next()
        tokens.expect('-p')
        rule['proto'] = tokens.next()
        assert rule['proto'] in ('tcp', 'udp')

        while tokens.peek() in ('-s', '-d', '--sport', '--dport', '-m'):
            flag = tokens.next()
            assert flag not in rule['match'], f"duplicate {flag}"
            if flag in ('-s', '-d'):
                value = tokens.next()
                check_ip(value)
            elif flag == '-m':
                tokens.expect('u32', '--u32')
                value = tokens.next()
                assert value == '4&0x8000=0x8000'
            else:
                value = tokens.next()
                low, _, high = value.partition(':')
                check_port(low if not high else f"{low}-{high}", allow_range=True)
            rule['match'][flag] = value

        tokens.expect('-j')
        rule['target'] = tokens.next()
        if rule['target'] == 'DROP':
            assert rule['table'] == 'mangle'
        else:
            assert rule['table'] == 'nat'
            assert rule['target'] == ('DNAT' if rule['chain'] == 'PREROUTING' else 'SNAT')
            tokens.expect('--to-destination' if rule['target'] == 'DNAT' else '--to-source')
            to = tokens.next()
            ip, colon, port = to.partition(':')
            assert ip or port, "NAT without ip or port"
            if ip:
                check_ip(ip)
            if colon:
                check_port(port, allow_range=False)
            rule['to'] = to

        assert tokens.done()
        rules.append(rule)

    return rules


class ScriptGrammarTest(unittest.TestCase):
    """Every combination of options must produce a script that parses."""

    def test_all_option_combinations_are_valid(self):
        options = product(
            (FLOWER, U32),
            ('tcp', 'udp'),
            ('ingress', 'egress'),
            ('', 'pref 1'),
            (False, True),
            (False, True),
        )
        for mode, protocol, direction, priority, cont, drop in options:
            for src_ip, dst_ip, src_port, dst_port in product(('', '1.1.1.1'), ('', '3.3.3.3'), ('', '80'), ('', '443')):
                config = make_config(
                    mode=mode, protocol=protocol, direction=direction, priority=priority,
                    continue_filtering=cont, drop_packet=drop,
                    src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
                    patch_src_ip='2.2.2.2', patch_dst_port='8080',
                )
                with self.subTest(config=config):
                    self.assertIsNone(Gen.validate(config))
                    parse_script(Gen.generate_commands(config))

    def test_ranges_are_valid(self):
        for mode in (FLOWER, U32):
            parse_script(generate(mode=mode, src_port='1000-1009', patch_src_port='2000-2009', dst_port='53', patch_dst_ip='9.9.9.9'))
            parse_script(generate(mode=mode, dst_port='1000-1009', patch_src_ip='9.9.9.9'))
            parse_script(generate(mode=mode, dst_port='1000-1009', patch_dst_port='1'))

    def test_icmp_like_protocols_without_ports_are_not_offered(self):
        # protocol other than tcp/udp: ports are ignored entirely
        commands = generate(protocol='icmp', src_port='80', dst_port='1-5', patch_src_ip='2.2.2.2', patch_src_port='9')
        self.assertEqual(len(commands), 2)
        self.assertNotIn('port', commands[1])
        self.assertNotIn('sport', commands[1])


class FilterSemanticsTest(unittest.TestCase):
    def test_empty_filter_means_all(self):
        for mode in (FLOWER, U32):
            (parsed,) = parse_script(generate(mode=mode, patch_src_ip='2.2.2.2'))
            self.assertEqual(set(parsed['match']), {'proto'})

    def test_catch_all_values_mean_all(self):
        for mode in (FLOWER, U32):
            (parsed,) = parse_script(generate(
                mode=mode, src_ip='0.0.0.0', dst_ip='0.0.0.0/0', src_port='1-65535', dst_port='1-65535', drop_packet=True))
            self.assertEqual(set(parsed['match']), {'proto'})

    def test_flower_values(self):
        (parsed,) = parse_script(generate(src_ip='1.1.1.1', dst_ip='3.3.3.3', src_port='80', dst_port='100-200', drop_packet=True))
        self.assertEqual(parsed['match'], {'proto': 'tcp', 'src_ip': '1.1.1.1', 'dst_ip': '3.3.3.3',
                                           'src_port': '80', 'dst_port': '100-200'})

    def test_u32_values(self):
        (parsed,) = parse_script(generate(mode=U32, protocol='udp', src_ip='1.2.3.4', dst_port='53', drop_packet=True))
        self.assertEqual(parsed['match'], {'proto': '17', 'src_ip': '0x01020304', 'dst_port': '53'})

    def test_single_port_range_is_a_single_port(self):
        (parsed,) = parse_script(generate(src_port='80-80', drop_packet=True))
        self.assertEqual(parsed['match']['src_port'], '80')

    def test_priority(self):
        self.assertIn(' pref 1 ', generate(priority='pref 1', drop_packet=True)[1])
        self.assertNotIn('pref', generate(drop_packet=True)[1])

    def test_u32_ports_use_transport_header_offset(self):
        command = generate(mode=U32, src_port='80', drop_packet=True)[1]
        self.assertIn('at nexthdr+0', command)


class ActionSemanticsTest(unittest.TestCase):
    def test_drop_ignores_patch_fields(self):
        for mode in (FLOWER, U32):
            (parsed,) = parse_script(generate(mode=mode, drop_packet=True, patch_src_ip='2.2.2.2', patch_dst_port='1'))
            self.assertEqual(parsed['action'], 'drop')
            self.assertEqual(parsed['patch'], {})

    def test_empty_patch_fields_are_left_alone(self):
        (parsed,) = parse_script(generate(src_ip='1.1.1.1', patch_dst_ip='2.2.2.2'))
        self.assertEqual(parsed['patch'], {'dst_ip': '2.2.2.2'})

    def test_flower_patch_values(self):
        (parsed,) = parse_script(generate(
            protocol='udp', patch_src_ip='2.2.2.2', patch_dst_ip='4.4.4.4', patch_src_port='5', patch_dst_port='6'))
        self.assertEqual(parsed['patch'], {'src_ip': '2.2.2.2', 'dst_ip': '4.4.4.4', 'src_port': '5', 'dst_port': '6'})
        self.assertIn('munge udp sport set 5', generate(protocol='udp', patch_src_port='5')[1])

    def test_u32_patch_values(self):
        (parsed,) = parse_script(generate(mode=U32, patch_src_ip='2.2.2.2', patch_dst_port='6'))
        self.assertEqual(parsed['patch'], {'src_ip': '0x02020202', 'dst_port': '6'})

    def test_pipe_and_continue(self):
        self.assertTrue(generate(patch_src_ip='2.2.2.2')[1].endswith(' pipe;'))
        self.assertTrue(generate(patch_src_ip='2.2.2.2', continue_filtering=True)[1].endswith(' continue;'))

    def test_filter_range_with_single_port_action_is_one_filter(self):
        for mode in (FLOWER, U32):
            commands = generate(mode=mode, src_port='1000-1003', patch_src_port='9')
            self.assertEqual(len(commands), 1 + (1 if mode == FLOWER else 4))
            for parsed in parse_script(commands):
                self.assertEqual(parsed['patch'], {'src_port': '9'})

    def test_filter_range_without_action_port_leaves_port_alone(self):
        (parsed,) = parse_script(generate(src_port='1000-1003', patch_dst_ip='2.2.2.2'))
        self.assertEqual(parsed['match']['src_port'], '1000-1003')
        self.assertEqual(parsed['patch'], {'dst_ip': '2.2.2.2'})


class EvilBitTest(unittest.TestCase):
    def test_filter_matches_the_evil_bit(self):
        (parsed,) = parse_script(generate(mode=U32, evil_bit=True, drop_packet=True))
        self.assertEqual(parsed['match']['evil_bit'], '0x8000')
        self.assertIn('match u16 0x8000 0x8000 at 6', Gen.generate_commands(make_config(mode=U32, evil_bit=True, drop_packet=True))[1])

    def test_action_sets_only_the_evil_bit(self):
        for mode in (FLOWER, U32):
            (parsed,) = parse_script(generate(mode=mode, patch_evil_bit=True))
            self.assertEqual(parsed['patch'], {'evil_bit': '0x8000'})
        self.assertIn('munge offset 6 u16 set 0x8000 retain 0x8000', generate(patch_evil_bit=True)[1])

    def test_evil_bit_action_alone_is_a_valid_action(self):
        self.assertIsNone(Gen.validate(make_config(patch_evil_bit=True)))

    def test_evil_bit_filter_needs_u32(self):
        self.assertIsNotNone(Gen.validate(make_config(mode=FLOWER, evil_bit=True, drop_packet=True)))
        self.assertIsNone(Gen.validate(make_config(mode=U32, evil_bit=True, drop_packet=True)))

    def test_evil_bit_action_is_ignored_when_dropping(self):
        (parsed,) = parse_script(generate(patch_evil_bit=True, drop_packet=True))
        self.assertEqual(parsed['patch'], {})

    def test_combined_with_other_fields(self):
        (parsed,) = parse_script(generate(mode=U32, evil_bit=True, src_ip='1.1.1.1', src_port='80',
                                          patch_evil_bit=True, patch_dst_ip='2.2.2.2'))
        self.assertEqual(set(parsed['match']), {'proto', 'evil_bit', 'src_ip', 'src_port'})
        self.assertEqual(set(parsed['patch']), {'evil_bit', 'dst_ip'})


class IptablesTest(unittest.TestCase):
    def test_drop(self):
        (command,) = generate(mode=IPT, src_ip='1.1.1.1', dst_port='100-200', drop_packet=True)
        self.assertEqual(command, 'iptables -t mangle -A PREROUTING -i eth0 -p tcp -s 1.1.1.1 --dport 100:200 -j DROP;')

    def test_no_tc_lines_are_generated(self):
        for command in generate(mode=IPT, drop_packet=True, direction='egress'):
            self.assertTrue(command.startswith('iptables '))

    def test_empty_filter_means_all(self):
        (rule,) = parse_iptables(generate(mode=IPT, drop_packet=True, src_ip='0.0.0.0', src_port='1-65535'))
        self.assertEqual(rule['match'], {})

    def test_ingress_rewrites_destination(self):
        (rule,) = parse_iptables(generate(mode=IPT, src_ip='1.1.1.1', patch_dst_ip='2.2.2.2', patch_dst_port='8080'))
        self.assertEqual((rule['chain'], rule['target'], rule['to']), ('PREROUTING', 'DNAT', '2.2.2.2:8080'))

    def test_egress_rewrites_source(self):
        (rule,) = parse_iptables(generate(mode=IPT, direction='egress', protocol='udp', patch_src_ip='2.2.2.2'))
        self.assertEqual((rule['chain'], rule['target'], rule['iface'], rule['to']), ('POSTROUTING', 'SNAT', 'eth0', '2.2.2.2'))

    def test_port_only_rewrite(self):
        (rule,) = parse_iptables(generate(mode=IPT, patch_dst_port='8080'))
        self.assertEqual(rule['to'], ':8080')

    def test_priority_inserts_first(self):
        (rule,) = parse_iptables(generate(mode=IPT, priority='pref 1', drop_packet=True))
        self.assertTrue(rule['insert'])

    def test_evil_bit_match(self):
        (rule,) = parse_iptables(generate(mode=IPT, evil_bit=True, drop_packet=True))
        self.assertEqual(rule['match']['-m'], '4&0x8000=0x8000')

    def test_port_ranges_map_one_to_one(self):
        rules = parse_iptables(generate(mode=IPT, dst_port='1000-1002', patch_dst_port='2000-2002'))
        self.assertEqual([(r['match']['--dport'], r['to']) for r in rules],
                         [('1000', ':2000'), ('1001', ':2001'), ('1002', ':2002')])

    def test_filter_range_is_kept_as_a_single_rule(self):
        (rule,) = parse_iptables(generate(mode=IPT, dst_port='1000-1002', patch_dst_ip='2.2.2.2'))
        self.assertEqual(rule['match']['--dport'], '1000:1002')

    def test_unsupported_actions_are_rejected(self):
        for overrides in (
            dict(patch_src_ip='2.2.2.2'),                                  # ingress can't rewrite the source
            dict(patch_dst_ip='2.2.2.2', patch_src_port='5'),
            dict(direction='egress', patch_dst_ip='2.2.2.2'),              # egress can't rewrite the destination
            dict(direction='egress', patch_src_ip='2.2.2.2', patch_dst_port='5'),
            dict(patch_dst_ip='2.2.2.2', patch_evil_bit=True),
            dict(patch_dst_ip='2.2.2.2', continue_filtering=True),
            dict(patch_evil_bit=True),
        ):
            self.assertIsNotNone(Gen.validate(make_config(mode=IPT, **overrides)), overrides)

    def test_unsupported_action_fields_are_ignored_when_dropping(self):
        self.assertIsNone(Gen.validate(make_config(mode=IPT, drop_packet=True, patch_src_ip='2.2.2.2', patch_evil_bit=True)))

    def test_count_rules(self):
        self.assertEqual(Gen.count_rules(generate(mode=IPT, dst_port='1-3', patch_dst_port='11-13')), 3)
        self.assertEqual(Gen.count_rules(generate(src_port='1-3', patch_src_port='11-13')), 3)


class PortRangeMappingTest(unittest.TestCase):
    def test_ranges_map_one_to_one(self):
        for mode in (FLOWER, U32):
            filters = parse_script(generate(mode=mode, src_port='1000-1004', patch_src_port='2000-2004'))
            self.assertEqual([f['match']['src_port'] for f in filters], [str(p) for p in range(1000, 1005)])
            self.assertEqual([f['patch']['src_port'] for f in filters], [str(p) for p in range(2000, 2005)])

    def test_src_and_dst_ranges_are_a_cartesian_product(self):
        filters = parse_script(generate(src_port='10-11', patch_src_port='20-21', dst_port='30-32', patch_dst_port='40-42'))
        pairs = [((f['match']['src_port'], f['match']['dst_port']), (f['patch']['src_port'], f['patch']['dst_port']))
                 for f in filters]
        expected = [((str(10 + i), str(30 + j)), (str(20 + i), str(40 + j))) for i in range(2) for j in range(3)]
        self.assertEqual(pairs, expected)

    def test_overlapping_ranges_map_by_position(self):
        filters = parse_script(generate(src_port='100-102', patch_src_port='101-103'))
        self.assertEqual([(f['match']['src_port'], f['patch']['src_port']) for f in filters],
                         [('100', '101'), ('101', '102'), ('102', '103')])

    def test_script_has_exactly_one_qdisc(self):
        commands = generate(src_port='1-5', patch_src_port='11-15')
        self.assertEqual(sum(' qdisc ' in c for c in commands), 1)
        self.assertEqual(len(commands), 6)


class ValidationTest(unittest.TestCase):
    def assertInvalid(self, **overrides):
        config = make_config(**overrides)
        if 'patch_src_ip' not in overrides and not any(
                overrides.get(k) for k in ('patch_dst_ip', 'patch_src_port', 'patch_dst_port')):
            config.setdefault('drop_packet', True)
        self.assertIsNotNone(Gen.validate(config), overrides)

    def assertValid(self, **overrides):
        config = make_config(**overrides)
        self.assertIsNone(Gen.validate(config), overrides)

    def test_interface(self):
        for name in ('', 'a b', 'a/b', 'a:b', 'x' * 16):
            self.assertInvalid(interface=name, drop_packet=True)
        for name in ('eth0', 'wlan0.100', 'x' * 15):
            self.assertValid(interface=name, drop_packet=True)

    def test_ips(self):
        for ip in ('1.1.1', '256.1.1.1', 'abc', '::1', '1.1.1.1/24', ' '):
            self.assertInvalid(src_ip=ip, drop_packet=True)
            self.assertInvalid(dst_ip=ip, drop_packet=True)
            self.assertInvalid(patch_src_ip=ip)
            self.assertInvalid(patch_dst_ip=ip)

    def test_filter_ports(self):
        for port in ('0', '65536', '-1', 'x', '5-1', '1-', '-5', '1-2-3', '0-10', '1-65536', '80,81'):
            self.assertInvalid(src_port=port, drop_packet=True)
            self.assertInvalid(dst_port=port, drop_packet=True)
        for port in ('1', '65535', '1-65535', '100-200'):
            self.assertValid(src_port=port, drop_packet=True)

    def test_action_ports(self):
        for port in ('0', '65536', 'x', '5-1', '1-', '1-65536'):
            self.assertInvalid(patch_src_port=port)
            self.assertInvalid(patch_dst_port=port)
        self.assertValid(patch_src_port='65535')

    def test_action_range_must_match_filter_range_size(self):
        self.assertInvalid(src_port='10-20', patch_src_port='10-15')
        self.assertInvalid(dst_port='10-20', patch_dst_port='10-31')
        self.assertInvalid(src_port='10', patch_src_port='20-21')
        self.assertInvalid(src_port='', patch_src_port='20-21')
        self.assertValid(src_port='10-20', patch_src_port='30-40')
        self.assertValid(src_port='10-20', patch_src_port='30')

    def test_action_must_patch_something(self):
        self.assertInvalid(src_ip='1.1.1.1')
        self.assertValid(src_ip='1.1.1.1', drop_packet=True)
        self.assertValid(patch_dst_ip='2.2.2.2')

    def test_ports_are_ignored_for_non_port_protocols(self):
        self.assertValid(protocol='icmp', src_port='bogus', patch_src_ip='2.2.2.2')
        self.assertInvalid(protocol='icmp', patch_src_port='9')

    def test_invalid_action_is_ignored_when_dropping(self):
        self.assertValid(drop_packet=True, patch_src_ip='bogus', patch_src_port='bogus')

    def test_filter_count_limit(self):
        limit = Gen.MAX_FILTERS
        self.assertValid(src_port=f'1-{limit}', patch_src_port=f'2001-{2000 + limit}')
        self.assertInvalid(src_port=f'1-{limit + 1}', patch_src_port=f'2001-{2001 + limit}')
        self.assertInvalid(src_port='1-40', patch_src_port='101-140', dst_port='1-40', patch_dst_port='101-140')
        # u32 has no ranges, so even a plain filter range is expanded
        self.assertInvalid(mode=U32, src_port='1-5000', drop_packet=True)
        self.assertValid(mode=FLOWER, src_port='1-5000', drop_packet=True)

    def test_any_filter_with_whole_range_action_is_too_big(self):
        self.assertInvalid(patch_src_port='1-65535')


if __name__ == '__main__':
    unittest.main()
