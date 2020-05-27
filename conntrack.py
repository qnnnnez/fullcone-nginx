import subprocess
import enum
import signal
import xml.etree.ElementTree as ET
import os
import ipaddress


class ConntrackCli:
    def __init__(self, bin_path):
        self.bin_path = bin_path

    def launch_process(self):
        # pull event in realtime, print to stdout in xml
        cmdline = [self.bin_path, '-E', '-o', 'xml']
        conntrack_process = subprocess.Popen(cmdline, stdout=subprocess.PIPE)
        
        # skip first 2 lines
        conntrack_process.stdout.readline()    # namespace
        conntrack_process.stdout.readline()    # root element start tag

        self.process = conntrack_process

    def read_one_event(self):
        # block until data avaliable
        event_xml = ET.fromstring(self.process.stdout.readline())
        return event_xml

    def stop(self):
        self.process.send_signal(signal.SIGINT)


class L3L4:
    def __init__(self, xml_element):
        self.l3_proto = xml_element.find('.//layer3').attrib['protoname']
        self.l3_src = xml_element.find('.//layer3/src').text
        self.l3_dst = xml_element.find('.//layer3/dst').text
        self.l4_proto = xml_element.find('.//layer4').attrib['protoname']
        try:
            self.l4_sport = xml_element.find('.//layer4/sport').text
            self.l4_dport = xml_element.find('.//layer4/dport').text
        except AttributeError:
            pass

class FlowEvent:
    def __init__(self, xml_element):
        original = xml_element.find('.//meta[@direction="original"]')
        reply = xml_element.find('.//meta[@direction="reply"]')

        self.original = L3L4(original)
        self.reply = L3L4(reply)
        self.id = xml_element.find('.//id').text
        self.type = xml_element.attrib['type']


class FlowEventListener:
    def __init__(self, cli):
        self._cli = cli
        self.flow_table = {}
        self.stopped = False
        self.stop_cli = False

    def run(self):
        if self.stopped:
            raise RuntimeError()

        self._cli.launch_process()

        while not self.stopped:
            event = FlowEvent(self._cli.read_one_event())
            self.handle_event(event)

        if self.stop_cli:
            self._cli.stop()

    def handle_event(self, event):
        flow_id = event.id
        if event.type in ('new', 'update'):
            self.flow_table[flow_id] = event
            self.flow_table_updated(event)
        elif event.type == 'destroy':
            if flow_id in self.flow_table:
                del self.flow_table[flow_id]
                self.flow_table_updated(event)

    def flow_table_updated(self, event):
        pass

    def stop(self):
        self.stopped = True

class NginxFlowEventListener(FlowEventListener):
    def __init__(self, config_file_path, reload_execv, allowed_networks, additional_conf='', *args, **kwargs):
        self.config_file_path = config_file_path
        self.reload_execv = reload_execv
        self.additional_conf = additional_conf
        self.allowed_networks = allowed_networks
        super().__init__(*args, **kwargs)

    def check_flow(self, event):
        tcp_or_udp = ('tcp', 'udp')
        # only handle connection in IPv4 and TCP/UDP
        if (event.original.l3_proto != 'ipv4'
            or event.original.l4_proto not in tcp_or_udp
            or event.reply.l3_proto != 'ipv4'
            or event.reply.l4_proto not in tcp_or_udp):
            return False

        if event.original.l4_proto != event.reply.l4_proto:
            # not likely to happen?
            return False

        if event.original.l3_src == event.reply.l3_dst:
            # NAT not performed
            return False

        # check ip whitelist
        single_host_network =  ipaddress.ip_network(event.original.l3_src + '/32')
        for network in self.allowed_networks:
            if is_subnet_of(single_host_network, network):
                return True
        return False



    def generate_nginx_conf(self):
        listened_addresses = set()
        lines = []
        for flow_id, flow in self.flow_table.items():
            if not self.check_flow(flow):
                continue

            forward_line_template = 'server {{ listen {listen_addr}; proxy_pass {dest_addr}; {additional_conf} }}\t# flowid={id}\n'
            listen_addr = flow.reply.l3_dst + ':' + flow.reply.l4_dport
            if listen_addr in listened_addresses:
                continue
            listened_addresses.add(listen_addr)
            if flow.reply.l4_proto == 'udp':
                listen_addr += ' udp'
        
            dest_addr = flow.original.l3_src + ':' + flow.original.l4_sport
        
            line = forward_line_template.format(listen_addr=listen_addr, dest_addr=dest_addr, additional_conf=self.additional_conf, id=flow_id)
            lines.append(line)

        return ''.join(lines)

    def flow_table_updated(self, event):
        if not self.check_flow(event):
            return

        nginx_conf = self.generate_nginx_conf()
        tmp_conf_path = self.config_file_path + '.tmp'
        with open(tmp_conf_path, 'w') as f:
            f.write(nginx_conf)
        os.rename(tmp_conf_path, self.config_file_path)
        subprocess.Popen(self.reload_execv)


def is_subnet_of(a, b):
    try:
        # Always false if one is v4 and the other is v6.
        if a._version != b._version:
            raise TypeError(f"{a} and {b} are not of the same version")
        return (b.network_address <= a.network_address and
                b.broadcast_address >= a.broadcast_address)
    except AttributeError:
        raise TypeError(f"Unable to test subnet containment "
                        f"between {a} and {b}")

    
def main():
    import argparse
    import shlex
    parser = argparse.ArgumentParser(description='full-cone nat implemented in user mode')
    parser.add_argument('-n', '--nginx-conf', required=True)
    parser.add_argument('-r', '--nginx-reload-command', required=True)
    parser.add_argument('-c', '--conntrack-bin-path', required=True)
    parser.add_argument('-i', '--allowed-network', required=True, action='append')
    parser.add_argument('-a', '--additional-conf')
    args = parser.parse_args()
    allowed_networks = [ipaddress.ip_network(network) for network in args.allowed_network]
    cli = ConntrackCli(args.conntrack_bin_path)
    l = NginxFlowEventListener(
        config_file_path=args.nginx_conf,
        reload_execv=shlex.split(args.nginx_reload_command),
        cli=cli,
        allowed_networks=allowed_networks,
        additional_conf=args.additional_conf
        )

    try:
        l.run()
    except KeyboardInterrupt:
        l.stop_cli = True
        l.stop()

if __name__ == '__main__':
    main()
