# %ASA-2-106001: Inbound TCP connection denied from 10.132.0.147/2257 to 172.16.10.10/80 flags SYN  on interface inside
import unittest
import git
import os
import id_pkg as intrusion_detect

class TestInterface(unittest.TestCase):
    git_root = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
    syslog_file = os.path.join(git_root, 'data', 'test_interface.txt')
    # %ASA-2-106001: Inbound TCP connection denied from 10.132.0.147/2257 to 172.16.10.10/80 flags SYN on interface inside
    # Sep 12 2014 06:50:53 HOST : %ASA-2-106001: Inbound TCP connection denied from 10.132.0.147/2257 to 172.16.10.10/80 flags SYN on interface inside
    #   interface TestInterface
    info = {'Date': 'Sep 12 2014 06:50:53',
            'Host': 'HOST',
            'ID': '%ASA-2-106001',
            'Interface': 'TestInterface'}

    # Get the path to the data directory in the git repo
    git_root = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
    data_path = os.path.join(git_root, 'data')

    # Create a sample log file
    # https://docs.python.org/3/tutorial/inputoutput.html
    with open(syslog_file, 'w') as f:
        for ip_address_d in range(1,256,1):
            # Create the first part of the message
            log_string = info['Date'] + ' ' + info['Host'] + ' : ' + info['ID'] + ': '
            # Next add the source IP address message
            log_string = log_string + 'Inbound TCP connection denied from 10.132.0.147/2257 to '
            # Now add the destination IP
            log_string = log_string + '172.16.10.' + str(ip_address_d)
            # Terminate the message with the interface name
            log_string = log_string + '/80 flags SYN on interface inside ' + info['Interface'] + '\n'
            f.write(log_string)

    def test_interface_parse_log(self):
        # Create an IdParse object
        id_syslog = intrusion_detect.IdParse(self.syslog_file)

        # %ASA-2-106001: Inbound TCP connection denied from 10.132.0.147/2257 to 172.16.10.10/80 flags SYN  on interface inside
        # Check to make sure the ip spoofing information got added to the dataframe
        # Get a subset of the whole dataframe
        # s=spoof df=dataframe
        sdf = id_syslog.df[id_syslog.df['ID'] == 106001]

        # Expecting 255 total records
        self.assertEqual(255, len(sdf))

        # Expecting 1 source address
        self.assertTrue((sdf['Source'] == '10.132.0.147').all())

        # Expecting 1 source port
        self.assertTrue((sdf['SourcePort'] == '2257').all())

        # Expecting 255 unique destination addresses
        self.assertEqual(255, sdf['Destination'].nunique())

        # Expecting 1 destination port
        self.assertTrue((sdf['DestinationPort'] == '80').all())

    def test_inteface_stub(self):
        self.assertEqual(True, True)

    def test_has_interface(self):
        id_syslog = intrusion_detect.IdParse(self.syslog_file)
        # The test file generated has ip spoofing present
        # so expect this to return true
        self.assertTrue(id_syslog.has_interface())

if __name__ == '__main__':
    unittest.main()
