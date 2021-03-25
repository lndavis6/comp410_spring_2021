import unittest
import os
import git
import random
import id_pkg


class TestDenialOfService(unittest.TestCase):
    git_root = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
    syslog_file = os.path.join(git_root, 'data', 'denial_of_service.txt')

    def test_denial_of_service_stub(self):
        self.assertEqual(True, True)


    # %ASA-4-109017: User at IP_address exceeded auth proxy connection limit (max)
    info = {
        'Date': 'Mar 28 2021 06:50:53',
        'Host': 'TEAMNULL',
        'ID': '%ASA-4-109017',
    }

    # Create a sample log file
    with open(syslog_file, 'w') as f:
        for ip_address_d in range(1,256,1):
            # Create the first part of the message
            log_string = info['Date'] + ' ' + info['Host'] + ' : ' + info['ID'] + ': '
            # Next add the source IP address message
            log_string = log_string + 'User at 10.203.254.158'
            # Terminate the message
            log_string = log_string + ' exceeded auth proxy connection limit (max)' + '\n'
            f.write(log_string)

    def test_denial_of_service_parse_log(self):
        # Create an IdParse object
        id_syslog = id_pkg.IdParse(self.syslog_file)

        # Check to make sure the information got added to the dataframe
        # Get a subset of the whole dataframe
        # dss=denial of service df=dataframe
        dosdf = id_syslog.df[id_syslog.df['ID'] == 109017]

        # Expecting 255 total records
        self.assertEqual(255, len(dosdf))

        # Expecting 1 non-unique source address
        self.assertTrue((dosdf['Source'] == '10.203.254.158').all())

    def test_has_dos_attack(self):
        id_syslog = id_pkg.IdParse(self.syslog_file)
        self.assertTrue(id_syslog.has_dos_attack())


if __name__ == '__main__':
    unittest.main()
