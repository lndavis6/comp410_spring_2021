import unittest
import git
import os
import id_pkg as intrusion_detect
# import pandas as pd

class TestScanningThreat(unittest.TestCase):
    # Get the path to the data directory in the git repo
    git_root = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
    syslog_file = os.path.join(git_root, 'data', 'scanning_threat.txt')

    # % ASA - 4 - 733101: Object objectIP ( is targeted | is attacking). Current burst rate is rate_val per second,
    # max configured rate is rate_val; Current average rate is rate_val per second, max configured rate is rate_val;
    # Cumulative total count is total_cnt.

    info = {'Date': 'Mar 30 2021 03:30:30',
            'Host': 'TEAMNULL',
            'Type': 'targeted',
            'ID': '%ASA-4-733101',
            'burst_rate': '20',
            'max_rate1' : '30',
            'average_rate' : '15',
            'max_rate2' : '32',
            'total_cnt': '100'}

    # Create a sample log file
    with open(syslog_file, 'w') as f:
        for ip_address_d in range(1, 256, 1):
            # Create first part of the message
            log_string = info['Date'] + ' ' + info['Host'] + ' : ' + info['ID'] + ': '
            # Next add whether the port is attacking or being targeted
            log_string = log_string + ' 10.11.11.' + str(ip_address_d) + ' is ' + info['Type'] + '. '
            # Next add all of the burst rates
            log_string = log_string + 'Current burst rate is ' + info['burst_rate'] + ' per second, '
            log_string = log_string + 'max configured rate is ' + info['max_rate1'] + '; '
            log_string = log_string + 'Current average rate is ' + info['average_rate'] + ' per second, '
            log_string = log_string + 'max configured rate is ' + info['max_rate2'] + '; '
            log_string = log_string + 'Cumulative total count is ' + info['total_cnt'] + '\n'
            f.write(log_string)

    def test_scanning_threat_stub(self):
        self.assertEqual(True, True)

    def test_scanning_threat_parse_log(self):
        id_syslog = intrusion_detect.IdParse(self.syslog_file)

        # st = scanning threat df = data frame
        stdf = id_syslog.df[id_syslog.df['ID'] == 733101]

        # expecting a list of 255
        self.assertEqual(255, len(stdf))

        # expecting burst rates above 0
        self.assertTrue((stdf['Burst_Rate'] > 0).all())
        self.assertTrue((stdf['Max Configured Rate 1'] > 0).all())
        self.assertTrue((stdf['Average Rate'] > 0).all())
        self.assertTrue((stdf['Max Configured Rate 2'] > 0).all())
        self.assertTrue((stdf['Total Count'] > 0).all())

    def test_has_scanning_threat(self):
        id_syslog = intrusion_detect.IdParse(self.syslog_file)
        self.assertTrue(id_syslog.has_scanning_threat())


if __name__ == '__main__':
    unittest.main()
