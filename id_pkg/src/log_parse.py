import pandas as pd
import re


class LogParse:
    """Parser for firewall logs"""
    def log_parse_id(self):
        """For testing purposes simply return a text message"""
        return 'LogParse'

    def handle_message(self, df, id):
        """Handles specific syslog messages"""
        # https://regex101.com
        # https://developers.google.com/edu/python/regular-expressions
        # https://www.w3schools.com/python/python_regex.asp
        # https://rosie-lang.org

        # %ASA-1-103004: (Primary) Other firewall reports this firewall failed. Reason: reason-string.
        # Parse the reason out of the text string
        if id == 103004:
            (message, reason) = df.loc[id, 'Text'].split('Reason: ')
            df.loc[id, 'Reason'] = reason.rstrip()

        if id == 114003:
            # %ASA-1-114003: Failed to run cached commands in 4GE SSM I/O card (error error_string)
            match = re.search(r'error (\w+)', df.loc[id, 'Text'])
            if match:
                df.loc[id, 'Error'] = match.group(1)

        if id == 326028:
            # %ASA-3-326028: Asynchronous error: error_message
            m = re.search(r' error: (\w+)', df.loc[id, 'Text'])
            if m:
                df.loc[id, 'Error'] = m.group(1)
        if id == 105003:
            #%ASA-1-105003: (Primary) Monitoring on interface interface_name waiting
            m = re.search(r' interface (\w+\s\w+)', df.loc[id, 'Text'])
            if m:
                df.loc[id, 'Interface'] = m.group(1)

        if id == 105008:
            #Implement %ASA-1-105008: (Primary) Testing interface interface_name.
            m = re.search(r' interface (\w+)', df.loc[id, 'Text'])
            if m:
                df.loc[id, 'Interface'] = m.group(1)

        if id == 105004:
            # %ASA-1-105004: (Primary) Monitoring on interface interface_name normal
            m = re.search(r' interface (\w+\s\w+)', df.loc[id, 'Text'])
            if m:
                df.loc[id, 'Interface'] = m.group(1)

        if id == 114017:
            # %ASA-3-114017: Failed to get link status in 4GE SSM I/O card (error error_string).
            m = re.search(r' error: (\w+)', df.loc[id, 'Text'])

        if id == 114018:
            # %ASA-3-114018: Failed to set port speed in 4GE SSM I/O card (error error_string).
            m = re.search(r'error (\w+)', df.loc[id, 'Text'])
            if m:
                df.loc[id, 'Error'] = m.group(1)

        if id == 114002:
            # %ASA-1-114002: Failed to initialize SFP in 4GE SSM I/O card (error error_string)
            m = re.search(r'error (\w+)', df.loc[id, 'Text'])
            if m:
                df.loc[id, 'Error'] = m.group(1)

        if id == 114001:
            # %ASA-1-114001: Failed to initialize 4GE SSM I/O card (error error_string).
            m = re.search(r'error (\w+)', df.loc[id, 'Text'])
            if m:
                df.loc[id, 'Error'] = m.group(1)

        if id == 114001:
            # %ASA-1-114001: Failed to initialize 4GE SSM I/O card (error error_string)
            x = re.search(r' \(error (\w+)\)', df.loc[id, 'Text'])
            if x:
                df.loc[id, 'Error'] = x.group(1)

        if id == 114002:
            # %ASA-1-114002: Failed to initialize SFP in 4GE SSM I/O card (error error_string).
            match = re.search(r'error (\w+)', df.loc[id, 'Text'])
            if match:
                df.loc[id, 'Error'] = match.group(1)

        if id == 114007:
            # %ASA-3-114007: Failed to get current msr in 4GE SSM I/O card (error error_string).
            match = re.search(r'error (\w+)', df.loc[id, 'Text'])
            if match:
                df.loc[id, 'Error'] = match.group(1)

        if id == 114019:
            # %ASA-3-114019: Failed to set media type in 4GE SSM I/O card (error error_string)
            match = re.search(r'error (\w+)', df.loc[id, 'Text'])
            if match:
                df.loc[id, 'Error'] = match.group(1)

        if id == 114018:
            # %ASA-3-114018: Failed to set port speed in 4GE SSM I/O card (error error_string).
            m = re.search(r'\(error (\w+)', df.loc[id, 'Text'])
            if m:
                df.loc[id, 'Error'] = m.group(1)

        # %ASA-3-114006: Failed to get port statistics in 4GE SSM I/O card (error error_string)
        if id == 114006:
            m = re.search(r'\(error (\w+)\)', df.loc[id, 'Text'])
            if m:
                df.loc[id, 'Error'] = m.group(1)

        return df

    def parse_syslog_file(self, syslog_file):
        """Returns a dataframe of parsed example syslogs"""

        # https://pandas.pydata.org/docs/user_guide/index.html
        df = pd.DataFrame()

        with open(syslog_file, encoding='utf-8') as f:
            for line in f:
                # %(Type)-(Severity)-(id): (Text)
                m = re.search(r'^%(\w+)-(\d)-(\d+): (.+)', line)
                # If the re matched
                if m:
                    id = int(m.group(3))
                    df.loc[id, 'Type'] = m.group(1)
                    df.loc[id, 'Severity'] = int(m.group(2))
                    df.loc[id, 'Text'] = m.group(4).rstrip()

                    df = self.handle_message(df, id)
        return df
