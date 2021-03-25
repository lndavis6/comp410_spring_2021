import unittest
import os
import git
import id_pkg as intrusion_detect
import pandas as pd

class TestFirewall(unittest.TestCase):
    #path to data directory and git repo
    git_root = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
    syslog_file = os.path.join(git_root, 'data', 'firewall.txt')

    #%ASA-3-713162: Remote user (session Id - id) has been rejected by the Firewall Server
    info = {'Date': 'March 10 2021 11:11:11',
            'Host': 'HOST',
            'ID': '%ASA-3-713162',
            'SessionID': 'db248b6cbdc547bbc6c6fdfb6916eeb'
             }

    #Creating sample log file
    with open(syslog_file,'w') as f:
        for session_id in range(1,256,1):
            # date of attack
            log_string = info['Date'] + ' ' + info['Host'] + ' : '
            # log message type/id
            log_string = log_string + info['ID'] + ': '
            # message
            log_string = log_string + 'Remote user '
            # session id
            log_string = log_string + '(' + info['SessionID'] + ' - ' + str(session_id) + ') '
            # finish message
            log_string = log_string + 'has been rejected by the Firewall Server' + '\n'
            f.write(log_string)

    def test_firewall_stub(self):
        self.assertEqual(True, True)

    def test_firewall_parse_log(self):
        id_syslog = intrusion_detect.IdParse(self.syslog_file)

        dataFrame = id_syslog.df[id_syslog.df['ID'] == 713162]

        #expecting list of 255
        self.assertEqual(255, len(dataFrame))

        # expecting 1 session id
        self.assertTrue((dataFrame['Session'] == 'db248b6cbdc547bbc6c6fdfb6916eeb').all())

        # expecting 255 unique id
        self.assertEqual(255,dataFrame['Identifier'].nunique())

    def test_has_firewall(self):
        id_syslog = intrusion_detect.IdParse(self.syslog_file)

        self.assertTrue(id_syslog.has_firewall())

if __name__ == '__main__':
    unittest.main()