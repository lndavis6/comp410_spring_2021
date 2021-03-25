# https://docs.python.org/3/library/unittest.html
import unittest
import id_pkg as intrusion_detect
import git
import os
#import pandas as pd


class LogParseTest(unittest.TestCase):
    """Unit test structure for LogParse"""
    # https://docs.python.org/3/library/unittest.html#unittest.TestCase

    # Find the path to the package directory in the current working git repo
    # Use os.path to make sure paths are platform independent
    # https://docs.python.org/3/library/os.path.html?highlight=os.path.join#os.path.join
    pkg_path = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
    data_path = os.path.join(pkg_path, 'data')

    def test_log_parse(self):
        """Basic test case to show that LogParse loads OK"""
        lp = intrusion_detect.LogParse()
        self.assertEqual('LogParse', lp.log_parse_id())

    def test_syslog_file(self):
        """Checks to make sure the syslog file appears valid"""
        # https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/b_syslog/syslogs-sev-level.html
        fname = 'syslogs.txt'

        # Open the syslog file
        # https://docs.python.org/3/tutorial/inputoutput.html
        with open(os.path.join(self.data_path, fname), encoding='utf-8') as f:
            line_num = 1
            for line in f:
                # create a string with the current file name and line number
                # for use in error messages
                ln = fname + ':' + str(line_num) + ' '

                # expect all lines to begin with %ASA-
                # https://docs.python.org/3/library/unittest.html#unittest.TestCase.assertRegex
                self.assertRegex(line, r'^%ASA-', ln + 'does not start with %ASA-')

                # Make sure there are no other %ASA which would indicate a
                # merged line or other problem in the syslog file
                self.assertNotRegex(line, r'.%ASA', ln + 'extra %ASA found')

                line_num += 1

    def test_parse_syslog_file(self):
        """Tests to make sure parse_syslog_file() works OK"""
        # Sample syslog file
        fname = 'syslogs.txt'

        # Create a LogParse object and parse the test syslog file
        lp = intrusion_detect.LogParse()
        # https://pandas.pydata.org/docs/user_guide/index.html
        df = lp.parse_syslog_file(os.path.join(self.data_path, fname))

        # %ASA-1-103004: (Primary) Other firewall reports this firewall failed. Reason: reason-string.
        self.assertTrue(df.loc[103004, 'Type'] == 'ASA')
        self.assertTrue(df.loc[103004, 'Severity'] == 1)
        self.assertTrue(df.loc[103004, 'Text'] == '(Primary) Other firewall reports this firewall failed. Reason: '
                                                  'reason-string.')
        self.assertTrue(df.loc[103004, 'Reason'] == 'reason-string.')

        # %ASA-1-114003: Failed to run cached commands in 4GE SSM I/O card (error error_string).
        self.assertTrue(df.loc[114003, 'Type'] == 'ASA')
        self.assertEqual(1, df.loc[114003, 'Severity'])
        self.assertEqual('Failed to run cached commands in 4GE SSM I/O card (error error_string).',
                         df.loc[114003, 'Text'])
        self.assertEqual('error_string', df.loc[114003, 'Error'])

        # %ASA-3-326028: Asynchronous error: error_message
        self.assertTrue(df.loc[326028, 'Type'] == 'ASA')
        # expected, actual
        self.assertEqual(3, df.loc[326028, 'Severity'])
        self.assertEqual('Asynchronous error: error_message', df.loc[326028, 'Text'])
        self.assertEqual('error_message', df.loc[326028, 'Error'])

        # %ASA-1-114001: Failed to initialize 4GE SSM I/O card (error error_string).
        self.assertTrue(df.loc[114001, 'Type'] == 'ASA')
        self.assertEqual(1, df.loc[114001, 'Severity'])
        self.assertEqual('Failed to initialize 4GE SSM I/O card (error error_string).', df.loc[114001, 'Text'])
        self.assertEqual('error_string', df.loc[114001, 'Error'])

        # %ASA-1-114002: Failed to initialize SFP in 4GE SSM I/O card (error error_string).
        self.assertTrue(df.loc[114002, 'Type'] == 'ASA')
        self.assertEqual(1, df.loc[114002, 'Severity'])
        self.assertEqual('Failed to initialize SFP in 4GE SSM I/O card (error error_string).', df.loc[114002, 'Text'])
        self.assertEqual('error_string', df.loc[114002, 'Error'])

        # %ASA-3-114007: Failed to get current msr in 4GE SSM I/O card (error error_string).
        self.assertTrue(df.loc[114007, 'Type'] == 'ASA')
        self.assertEqual(3, df.loc[114007, 'Severity'])
        self.assertEqual('Failed to get current msr in 4GE SSM I/O card (error error_string).', df.loc[114007, 'Text'])
        self.assertEqual('error_string', df.loc[114007, 'Error'])

        # %ASA-3-114019: Failed to set media type in 4GE SSM I/O card (error error_string)
        self.assertTrue(df.loc[114019, 'Type'] == 'ASA')
        self.assertEqual(3, df.loc[114019, 'Severity'])
        self.assertEqual('Failed to set media type in 4GE SSM I/O card (error error_string).', df.loc[114019, 'Text'])
        self.assertEqual('error_string', df.loc[114019, 'Error'])

        # %ASA-3-114018: Failed to set port speed in 4GE SSM I/O card (error error_string).
        self.assertTrue(df.loc[114018, 'Type'] == 'ASA')
        self.assertTrue(df.loc[114018, 'Severity'] == 3)
        self.assertTrue(df.loc[114018, 'Text'] == 'Failed to set port speed in 4GE SSM I/O card (error error_string).')
        self.assertTrue(df.loc[114018, 'Error'] == 'error_string')

        # %ASA-1-105003: (Primary) Monitoring on interface interface_name waiting
        self.assertEqual('ASA', df.loc[105003, 'Type'])
        self.assertEqual(1, df.loc[105003, 'Severity'])
        self.assertEqual('(Primary) Monitoring on interface interface_name waiting', df.loc[105003, 'Text'])
        self.assertEqual('interface_name waiting', df.loc[105003, 'Interface'])

        # %ASA-1-105008: (Primary) Testing interface interface_name.
        self.assertEqual('ASA', df.loc[105008, 'Type'])
        self.assertEqual(1, df.loc[105008, 'Severity'])
        self.assertEqual('(Primary) Testing interface interface_name.', df.loc[105008, 'Text'])
        self.assertEqual('interface_name', df.loc[105008, 'Interface'])

        # %ASA-1-105004: (Primary) Monitoring on interface interface_name normal
        self.assertTrue(df.loc[105004, 'Type'] == 'ASA')
        # expected, actual
        self.assertEqual(1, df.loc[105004, 'Severity'])
        self.assertEqual('(Primary) Monitoring on interface interface_name normal', df.loc[105004, 'Text'])
        self.assertEqual('interface_name normal', df.loc[105004, 'Interface'])

        # %ASA-3-114017: Failed to get link status in 4GE SSM I/O card (error error_string).
        self.assertTrue(df.loc[114017, 'Type'] == 'ASA')
        self.assertTrue(3, df.loc[114017, 'Severity'])
        self.assertTrue('Failed to get link status in 4GE SSM I/O card (error error_string).', df.loc[114017, 'Text'])
        self.assertTrue('error_message', df.loc[114017, 'Error'])

        # %ASA-3-114018: Failed to set port speed in 4GE SSM I/O card (error error_string).
        self.assertTrue(df.loc[114018, 'Type'] == 'ASA')
        # expected, actual
        self.assertEqual(3, df.loc[114018, 'Severity'])
        self.assertEqual('Failed to set port speed in 4GE SSM I/O card (error error_string).', df.loc[114018, 'Text'])
        self.assertEqual('error_string', df.loc[114018, 'Error'])

        # %ASA-1-114002: Failed to initialize SFP in 4GE SSM I/O card (error error_string)
        self.assertEqual('ASA', df.loc[114002, 'Type'])
        self.assertEqual(1, df.loc[114002, 'Severity'])
        self.assertEqual('Failed to initialize SFP in 4GE SSM I/O card (error error_string).', df.loc[114002, 'Text'])
        self.assertEqual('error_string', df.loc[114002, 'Error'])

        # %ASA-1-114001: Failed to initialize 4GE SSM I/O card (error error_string).
        self.assertTrue(df.loc[114001, 'Type'] == 'ASA')
        # expected, actual
        self.assertEqual(1, df.loc[114001, 'Severity'])
        self.assertEqual('Failed to initialize 4GE SSM I/O card (error error_string).', df.loc[114001, 'Text'])
        self.assertEqual('error_string', df.loc[114001, 'Error'])

        # %ASA-3-114006: Failed to get port statistics in 4GE SSM I/O card (error error_string)
        self.assertTrue(df.loc[114006, 'Type'] == 'ASA')
        # expected, actual
        self.assertEqual(3, df.loc[114006, 'Severity'])
        self.assertEqual('Failed to get port statistics in 4GE SSM I/O card (error error_string).',
                         df.loc[114006, 'Text'])
        self.assertEqual('error_string', df.loc[114006, 'Error'])


if __name__ == '__main__':
    unittest.main()
