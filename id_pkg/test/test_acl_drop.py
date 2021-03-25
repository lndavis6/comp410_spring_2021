import unittest
import git
import os
import id_pkg as intrusion_detect
import pandas as pd
import random


class TestACLDROP(unittest.TestCase):
    git_root = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
    syslog_file = os.path.join(git_root, 'data', 'acldrop.txt')

    # %ASA-4-733100: drop rate-1 exceeded. Current burst rate is 19 per second,
    # max configured rate is 0; Current average rate is 2 per second,
    # max configured rate is 0; Cumulative total count is 1472

    info = {
        'Date': 'March 28 2021 10:20:31',
        'Host': 'HOST',
        'ID': '%ASA-4-733100'

    }

    with open(syslog_file, 'w') as f:
        for i in range(1, 256, 1):
            dropRate = i
            burstRate = i
            MaxConfigRate1 = i
            CurrentAverageRate = i
            MaxConfigRate2 = i
            TotalCount = i
            # Create the first part of the message
            log_string = info['Date'] + ' ' + info['Host'] + ' : ' + info['ID'] + ': '

            # Drop rate
            log_string = log_string + 'drop rate-' + str(dropRate) + ' exceeded. '

            # Burst Rate
            log_string = log_string + 'Current burst rate is ' + str(burstRate) + ' per second, '

            # max config rate 1
            log_string = log_string + 'max configured rate is ' + str(MaxConfigRate1) + '; '

            # Current average
            log_string = log_string + 'Current average rate is ' + str(CurrentAverageRate) + ' per second, '

            # max config 2
            log_string = log_string + 'max configured rate is ' + str(MaxConfigRate2) + '; '

            # total count
            log_string = log_string + 'Cumulative total count is ' + str(TotalCount) + '\n'
            f.write(log_string)

    def test_acl_drop_stub(self):
        self.assertEqual(True, True)

    def test_acl_drop_parse_log(self):
        # Create an IdParse object
        id_syslog = intrusion_detect.IdParse(self.syslog_file)
        sdf = id_syslog.df[id_syslog.df['ID'] == 733100]
        # Expecting 255 total records
        self.assertEqual(255, len(sdf))
        # Expecting 255 unique destination addresses
        self.assertEqual(255, sdf['DropRate'].nunique())
        self.assertEqual(255, sdf['BurstRate'].nunique())
        self.assertEqual(255, sdf['MaxConfigRate1'].nunique())
        self.assertEqual(255, sdf['CurrentAverageRate'].nunique())
        self.assertEqual(255, sdf['MaxConfigRate2'].nunique())
        self.assertEqual(255, sdf['TotalCount'].nunique())

    def test_has_acldrop(self):
        id_syslog = intrusion_detect.IdParse(self.syslog_file)
        # The test file generated has ip spoofing present
        # so expect this to return true
        self.assertTrue(id_syslog.has_acldrop())


if __name__ == '__main__':
    unittest.main()
