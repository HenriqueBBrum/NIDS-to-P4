from appcontroller import AppController

class CustomAppController(AppController):

    def __init__(self, *args, **kwargs):
        AppController.__init__(self, *args, **kwargs)

    def start(self):
        print "Calling the default controller to populate table entries"
        AppController.start(self)

        # Set hosts interfaces MTU to 9000
        for host_name in self.topo._host_links:
            h = self.net.get(host_name)
            h.cmd('ifconfig {}-eth0 mtu 9000'.format(host_name))
            h.cmd('ifconfig {}-eth0 promisc'.format(host_name))
            h.cmd('ifconfig {}-eth0 txqueuelen 20000'.format(host_name))

        # Set SW interfaces MTU to 9000
        for host_name in self.topo._sw_links:
            h = self.net.get(host_name)
            h.cmd('ifconfig {}-eth1 mtu 9000'.format(host_name))
            h.cmd('ifconfig {}-eth1 txqueuelen 20000'.format(host_name))

            h.cmd('ifconfig {}-eth2 mtu 9000'.format(host_name))
            h.cmd('ifconfig {}-eth2 txqueuelen 20000'.format(host_name))

            h.cmd('ifconfig {}-eth3 mtu 9000'.format(host_name))
            h.cmd('ifconfig {}-eth3 txqueuelen 20000'.format(host_name))

        for host_name in self.topo._sw_links:
            h = self.net.get(host_name)
            h.cmd('cgcreate -g cpu:/lesscpulimited')
            h.cmd('cgset -r cpu.shares=512 cpulimited')

    def cmd_to_int(self, cmd):
        response = self.sendCommands([cmd])
        return int(response[0]['raw'])

    def cmd_to_string(self, cmd):
        response = self.sendCommands([cmd])
        return response[0]['raw'].replace('\n', '')

    def to_counter_value(self, counter_response):
        counter_value = counter_response.split('= ')[1]
        packets = int(counter_value.split('=')[1].split(',')[0])
        bytes = int(counter_value.split('=')[2].split(')')[0])
        return packets, bytes

    def stop(self):
        '''
        print("Collecting results")
        entries = self.cmd_to_int('table_num_entries ids')
        match_statistics = {}
        for i in range(entries):
            rule = self.cmd_to_string('table_dump_entry ids {}'.format(i))
            count = self.cmd_to_string('counter_read ingress.ids_rule_hit_counter {}'.format(i))
            packets, bytes = self.to_counter_value(count)
            match_statistics[rule] = packets

        print("Rules statistics\n")
        for rule in match_statistics.keys():
            print("Rule {}: {} packets".format(rule, match_statistics[rule]))
        '''
        received_pkt, received_bytes = self.to_counter_value(self.cmd_to_string('counter_read ingress.received 3'))
        redirected_normal_pkt, redirected_normal_bytes = self.to_counter_value(self.cmd_to_string('counter_read ingress.redirected 2'))
        redirected_ids_pkt, redirected_ids_bytes = self.to_counter_value(self.cmd_to_string('counter_read ingress.redirected 1'))
        ids_flow_pkt, ids_flow_bytes = self.to_counter_value(self.cmd_to_string('counter_read ingress.ids_flow 1'))

        print("Experiment results\n")
        print('Received: {} packets - {} bytes'.format(received_pkt, received_bytes))
        print('Redirected normal: {} packets - {} bytes'.format(redirected_normal_pkt, redirected_normal_bytes))
        print('Redirected ids: {} packets - {} bytes'.format(redirected_ids_pkt, redirected_ids_bytes))
        print('IDS Flow: {} packets - {} bytes'.format(ids_flow_pkt, ids_flow_bytes))

        AppController.stop(self)
