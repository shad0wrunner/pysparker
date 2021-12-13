import argparse
from base64 import b64encode
import json
import logging
import requests
from time import sleep
from urllib.parse import urlparse
import yaml


def norm_url(url):
    """ Normalizing URL for comparison purpose """
    return urlparse(url).netloc


def filename_sanitizer(filename):
    """ replaces potentially unsafe characters """

    logging.debug('Little bit of filename sanitizing')
    unacceptable = ['\\', '/', '&', '<', '>', '$', '|', '%', '?', '*', '"', ' ']
    for character in unacceptable:
        filename = filename.replace(character, '_')
    return filename


def parse_parameters():
    """ Parsing incoming parameters in one place and assigning them variables """

    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', action='store', help='Path to the configuration file (YAML)',
                        default='./config.yaml')
    parser.add_argument('-d', '--debug', action='store', help='Debug level',
                        default='INFO')
    parser.add_argument('-u', '--user', action='store', help='API userID',
                        default=None)
    parser.add_argument('-t', '--token', action='store', help='API Token',
                        default=None)
    parser.add_argument('-i', '--insecure', action='store_true', help='Allows connections with an incorrect SSL '
                                                                      'certificate')
    parser.add_argument('-g', '--group', action='store', help='Group name to start a group scanning',
                        default=None)

    args = parser.parse_args()
    parsed_args = (args.config, args.debug, args.user, args.token, args.insecure, args.group)
    return parsed_args


def get_api_token():
    """ Builds base64 API token """
    global api_token

    # trying to obtain username and token from cmd parameters
    api_user, api_user_token = parameters[2], parameters[3]
    if (api_user is None) or (api_user_token is None):
        logging.debug('Getting user and token from a config file')
        api_user = config['USERID']
        api_user_token = config['TOKEN']

    logging.info('Building API Token')
    string_to_encode = api_user + ':' + api_user_token
    api_token = b64encode(string_to_encode.encode()).decode()
    logging.debug('API token: %s' % api_token)
    return api_token


def get_policy_id(policy_name):
    """ Returns policy ID by policy name """

    api_handle = 'http://' + config['API_HOST'] + '/api/1.0/scanpolicies/get'
    headers = {
        'Authorization': "Basic " + api_token,
        'User-Agent': "Netfish",
        'Host': config['API_HOST'],
        'Content-Type': "application/json"
    }

    logging.info('Getting Policy Id for %s' % policy_name)
    json_response = json.loads(requests.request("GET", api_handle, headers=headers, params={'name': policy_name},
                                                verify=verify_ssl).text)
    policy_id = json_response['Id']
    logging.debug('Policy Id: %s' % policy_id)
    return policy_id


def get_websites_in_group(group_name):
    """ Gets a list of websites that belong to a specific group """

    websites_in_group = []
    list_websites_handle = 'http://' + config['API_HOST'] + '/api/1.0/websites/list'
    headers = {
        'Authorization': "Basic " + api_token,
        'User-Agent': "netfish",
        'Host': config['API_HOST'],
        'Content-Type': "application/json"
    }

    logging.debug('Fetching websites list')
    websites_list = json.loads(
        requests.request("GET", list_websites_handle, params={"pageSize": 200},
                         headers=headers, verify=verify_ssl).text)['List']

    # reverse search for registered groups in each website (because no such handle in API)
    for website in websites_list:
        logging.debug('Fetching groups list for %s' % website['Name'])
        for group in website['Groups']:
            if group['Name'] == group_name:
                websites_in_group.append(website['Name'])

    return websites_in_group


def get_website_name_from_scan(scan_id):
    """ Returns a website name from the given scan """

    scan_details_handle = 'http://' + config['API_HOST'] + '/api/1.0/scans/detail/' + scan_id
    headers = {
        'Authorization': "Basic " + api_token,
        'User-Agent': "netfish",
        'Host': config['API_HOST'],
        'Content-Type': "application/json"
    }

    # spams a lot. temporary not logged: logging.debug('Fetching scan details')
    # todo: store websites names to eliminate a need to fetch them every time
    website_name = json.loads(
        requests.request("GET", scan_details_handle, headers=headers, verify=verify_ssl).text)['WebsiteName']

    return website_name


def get_scans_list():
    """ Returns a list of running scans """

    list_scans_handle = 'http://' + config['API_HOST'] + '/api/1.0/scans/list'
    headers = {
        'Authorization': "Basic " + api_token,
        'User-Agent': "netfish",
        'Host': config['API_HOST'],
        'Content-Type': "application/json"
    }

    logging.debug('Fetching existing scans list')
    scans_list = json.loads(
        requests.request("GET", list_scans_handle, params={"pageSize": 200},
                         headers=headers, verify=verify_ssl).text)['List']

    return scans_list


def create_scan(scan_profile_name):
    """ Creates and runs a scan against specified URL """

    api_handle = 'http://' + config['API_HOST'] + '/api/1.0/scans/newwithprofile'
    headers = {
        'Authorization': "Basic " + api_token,
        'User-Agent': "netfish",
        'Host': config['API_HOST'],
        'Content-Type': "application/json"
    }

    # Building JSON request body to run new scan
    scan_json = \
        {"TargetUri": config['SCAN_URL'],
         "ProfileName": scan_profile_name
         }

    logging.info('Starting New Single Scan from \'%s\' profile' % scan_profile_name)

    scans_list = get_scans_list()
    for scan in scans_list:
        # checking if the scan already exists
        if norm_url(scan['TargetUrl']) == norm_url(config['SCAN_URL']) \
                and scan['State'] in ['Queued', 'Scanning', 'Pausing', 'Resuming']:
            logging.warning('Can\'t start a new scan. '
                            'Scan %s for %s is %s' % (scan['Id'], scan['TargetUrl'], scan['State']))
            return scan['Id'], scan['WebsiteName'], scan['State']

    logging.info('No other scans are active. Running a new scan')
    json_response = requests.request("POST", api_handle, data=json.dumps(scan_json), headers=headers,
                                     verify=verify_ssl)

    if json_response.status_code != 201:
        logging.critical('Error while starting scan: ' + json_response.text)
        exit(500)

    scan_id, scan_state = json.loads(json_response.text)['Id'], json.loads(json_response.text)['State']
    website_name = json.loads(json_response.text)['WebsiteName']
    logging.debug('Scan %s for %s is %s' % (scan_id, website_name, scan_state))

    return scan_id, website_name, scan_state


def create_group_scan(group_name, policy_id):
    """ Creates and runs scans against websites in a specified group. Returns scan ids and states """

    scan_states, scan_ids = [], []
    api_handle = 'http://' + config['API_HOST'] + '/api/1.0/scans/newgroupscan'
    headers = {
        'Authorization': "Basic " + api_token,
        'User-Agent': "netfish",
        'Host': config['API_HOST'],
        'Content-Type': "application/json"
    }

    # Building JSON request body to run new group scan
    scan_json = \
        {"PolicyId": policy_id,
         "WebsiteGroupName": group_name
         }

    logging.info('Starting New Group Scan on %s group' % group_name)
    json_response = requests.request("POST", api_handle, data=json.dumps(scan_json), headers=headers,
                                     verify=verify_ssl)
    started_scans = json.loads(json_response.text)  # retrieves what scans were started in the group

    for scan in started_scans:
        # gathering ids, site names and states of started scans
        scan_states.append({'Scan_Id': scan['Id'], 'Website_Name': scan['WebsiteName'], 'Scan_State': scan['State']})
        scan_ids.append(scan['Id'])
    logging.debug('Building scan states list: %s' % scan_states)

    # scans_list = get_scans_list()
    # todo: add a check for already running scans
    """ 
    for scan in scans_list:
        if norm_url(scan['TargetUrl']) == norm_url(config['SCAN_URL']) \
                and scan['State'] in ['Queued', 'Scanning', 'Pausing', 'Resuming']:
            logging.warning('Can\'t start a new scan. '
                            'Scan %s for %s is %s' % (scan['Id'], scan['TargetUrl'], scan['State']))
            return scan['Id'], scan['State']

    logging.info('No other scans are active. Running a new scan')
    """

    if json_response.status_code != 201:
        logging.error('Error while starting a group scan: ' + json_response.text)
        exit(500)
    else:
        logging.info('Scans started')

    return scan_states, scan_ids


def get_vulnerabilities_count(scan_id):
    """ fetches the report of the ongoing scan and returns counts of vulnerabilities """

    report_format = 'Json'
    vuln_count = {'Critical': 0,
                  'High': 0,
                  'Medium': 0,
                  'Low': 0,
                  'Information': 0,
                  'BestPractice': 0}

    api_handle = 'http://' + config['API_HOST'] + '/api/1.0/scans/report/'
    headers = {
        'Authorization': "Basic " + api_token,
        'User-Agent': "netfish",
        'Host': config['API_HOST'],
        'Content-Type': "application/json"
    }

    try:
        # todo: retrieve names without server request
        logging.info('Fetching vulnerabilities report for %s' % get_website_name_from_scan(scan_id))
        json_report = requests.request("GET", api_handle,
                                       params={"format": report_format,
                                               "id": scan_id,
                                               "type": "Vulnerabilities",
                                               "excludeResponseData": "true"},
                                       headers=headers, verify=verify_ssl)
        vulnerabilities = json.loads(json_report.text)['Vulnerabilities']

        logging.debug('Counting severities' + ' without AcceptedRisk and FalsePositive' *
                      (not include_accepted_and_falsepositives))
        for vulnerability in vulnerabilities:
            vulnerability_states = vulnerability['State'].split(', ')
            # checking if we need to count all issues even with an accepted risk - boolean check (not A and not B) or C
            if ('AcceptedRisk' not in vulnerability_states and 'FalsePositive' not in vulnerability_states) \
                    or include_accepted_and_falsepositives:
                severity = vulnerability['Severity']
                vuln_count[severity] += 1

        logging.debug("Vulnerabilities count: %s" % vuln_count)

    except json.decoder.JSONDecodeError as json_error:
        # catching JSON error in case API didn't answer with a correct response
        logging.error("JSON response wasn't properly retrieved. %s" % json_error)

    return vuln_count


def threshold_checker(critical, high, medium, low, info, bestpractice):
    """" Checks if the defined threshold for issues severities is reached and the script has to stop """

    threshold_reached = False
    max_threshold = f"Critical: {config['CRITICAL']}, " \
        f"High: {config['HIGH']}, " \
        f"Medium: {config['MEDIUM']}, " \
        f"Low: {config['LOW']}, " \
        f"Info: {config['INFO']}, " \
        f"Best Practice: {config['BESTPRACTICE']}"

    logging.info("Checking issues thresholds")

    # some boolean mathemagic here not to count -1 conditions
    if (critical > config['CRITICAL']) * (config['CRITICAL'] != -1) or \
            (high > config['HIGH']) * (config['HIGH'] != -1) or \
            (medium > config['MEDIUM']) * (config['MEDIUM'] != -1) or \
            (low > config['LOW']) * (config['LOW'] != -1) or \
            (info > config['INFO']) * (config['INFO'] != -1) or \
            (bestpractice > config['BESTPRACTICE']) * (config['BESTPRACTICE'] != -1):
        threshold_reached = True

    logging.debug("Threshold is: %s" % max_threshold)
    logging.debug("Threshold reached: %s" % threshold_reached)

    return threshold_reached


def scan_checker(scan_id):
    """ checks and returns current scan status """

    api_handle = 'http://' + config['API_HOST'] + '/api/1.0/scans/status/' + scan_id
    headers = {
        'Authorization': "Basic " + api_token,
        'User-Agent': "netfish",
        'Host': config['API_HOST'],
        'Content-Type': "application/json"
    }
    scan_state = json.loads(
        requests.request("GET", api_handle, params={"pageSize": 200},
                         headers=headers, verify=verify_ssl).text)['State']

    return scan_state


def get_group_scan_states(scan_ids):
    """ Updates current states of given scans """
    scan_states = []

    for scan_id in scan_ids:
        scan_states.append({'Scan_Id': scan_id,
                            'Website_Name': get_website_name_from_scan(scan_id),
                            'Scan_State': scan_checker(scan_id)})

    return scan_states


def get_scan_results(scan_id):
    """ returns the results of the scan in JSON for further integration (not used yet) """

    api_handle = 'http://' + config['API_HOST'] + '/api/1.0/scans/result/' + scan_id
    headers = {
        'Authorization': "Basic " + api_token,
        'User-Agent': "netfish",
        'Host': config['API_HOST'],
        'Content-Type': "application/json"
    }
    logging.info('Generating scan results')
    scan_results = json.loads(
        requests.request("GET", api_handle, params={"pageSize": 200},
                         headers=headers, verify=verify_ssl).text)

    return scan_results


def get_scan_report(scan_id, report_format):
    """ returns the results of the scan in Html or Pdf"""

    report_format = report_format.lower().capitalize()  # Ensure API gets a correct string

    api_handle = 'http://' + config['API_HOST'] + '/api/1.0/scans/report/'
    headers = {
        'Authorization': "Basic " + api_token,
        'User-Agent': "netfish",
        'Host': config['API_HOST'],
        'Content-Type': "application/json"
    }
    logging.info('Generating report')
    scan_report = requests.request("GET", api_handle,
                                   params={"format": report_format, "id": scan_id, "type": "ScanDetail"},
                                   headers=headers, verify=verify_ssl)

    if report_format == 'Html':
        scan_report = scan_report.text

    if report_format == 'Pdf':
        scan_report = scan_report.content

    return scan_report


def main():
    try:
        report_format = 'pdf'  # choosing report format - Pdf / Html
        get_api_token()  # retrieving API token to use in all requests
        group_name = parameters[5]  # name of the group for the group scan

        scan_states, scan_ids = [{}], []

        # checking if group was specified in parameters
        if group_name is None:
            scan_id, website_name, scan_state = create_scan(config['SCAN_PROFILE'])  # starting a new scan
            scan_ids.append(scan_id)
            scan_states[0].update({'Scan_Id': scan_id,
                                   'Website_Name': website_name,
                                   'Scan_State': scan_state})
        else:
            # checking if we need to use a specified policy for all scans or default ones from scan profiles
            policy_id = ''
            if config['POLICY_NAME']:
                policy_id = get_policy_id(config['POLICY_NAME'])
            scan_states, scan_ids = create_group_scan(group_name, policy_id)

        logging.debug('Vulnerabilities Threshold Check: %s' % config['BREAK_ON_THRESHOLD'])

        running_states = ['Scanning', 'Pausing', 'Queued', 'Resuming', 'Archiving']
        failed_states = ['Failed', 'Cancelled']
        scan_failed = False
        threshold_reached = False

        # constantly checking status of the scan
        # todo: add time-based exit so the script won't run forever if netsparker fails
        while [scan for scan in scan_states if scan['Scan_State'] in running_states]:
            try:
                scan_states = get_group_scan_states(scan_ids)
                logging.debug('The scans are %s' % scan_states)

                # continuous checking of a threshold only if the configuration parameter is True
                if config['BREAK_ON_THRESHOLD']:
                    for scan in scan_states:
                        scan_id = scan['Scan_Id']
                        vuln_count = get_vulnerabilities_count(scan_id)
                        threshold_reached += threshold_checker(*vuln_count.values())
                    if threshold_reached:
                        exit(config['THRESHOLD_EXIT_CODE'])

            except requests.exceptions.HTTPError as http_error:
                logging.error("HTTP Error: %s" % http_error,
                              exc_info=logging.getLogger().getEffectiveLevel() == logging.DEBUG)
            except requests.exceptions.ConnectionError as connection_error:
                logging.error("Connection Error: %s" % connection_error,
                              exc_info=logging.getLogger().getEffectiveLevel() == logging.DEBUG)
            except requests.exceptions.Timeout as timeout_error:
                logging.error("Timeout Error: %s" % timeout_error,
                              exc_info=logging.getLogger().getEffectiveLevel() == logging.DEBUG)
            except requests.exceptions.RequestException as other_errors:
                logging.error("I have a bad feeling about this: %s" % other_errors,
                              exc_info=logging.getLogger().getEffectiveLevel() == logging.DEBUG)

            logging.debug('Nothing important happened. Sleeping for %s seconds' % config['SCAN_POLLING_INTERVAL'])
            sleep(config['SCAN_POLLING_INTERVAL'])

        for scan in scan_states:
            # final vulnerabilities counting after the scan(s) was/were finished
            scan_id, scan_state = scan['Scan_Id'], scan['Scan_State']
            vuln_count = get_vulnerabilities_count(scan_id)
            if scan_state in failed_states:
                logging.error('The scan %s is %s. No report will be provided.' % (scan_id, scan_state))
                scan_failed = True

            # Threshold is True if boolean sum of all scans yields True
            threshold_reached += threshold_checker(*vuln_count.values())

            # fetching a report for the scan
            scan_report = get_scan_report(scan_id, report_format)

            with open(filename_sanitizer(scan['Website_Name']) + '.' + report_format,
                      'w' + 'b' * (report_format.lower() == 'pdf')) as f:
                logging.debug('Writing results to the report file: %s' % f.name)
                f.write(scan_report)

        if threshold_reached:
            exit(config['THRESHOLD_EXIT_CODE'])

        if scan_failed:
            exit(1)  # if at least 1 scan was cancelled or has failed - exit with error code 1

    except Exception as main_exception:
        logging.critical('Exception: %s' % main_exception,
                         exc_info=logging.getLogger().getEffectiveLevel() == logging.DEBUG)  # StackTrace only on DEBUG


if __name__ == '__main__':
    # retrieving command-line parameters
    parameters = parse_parameters()
    verify_ssl = parameters[4]

    # Configuring logging parameters
    log_level = parameters[1]
    log_format = "[%(levelname)s] (%(asctime)s): %(message)s"
    logging.getLogger('chardet.charsetprober').setLevel(logging.INFO)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.basicConfig(level=log_level, format=log_format)

    logging.info('Starting main module')
    logging.debug('Verifying invalid SSL certificates: %s' % verify_ssl)
    logging.debug('Loading config file')
    with open(parameters[0], 'r') as config_file:
        try:
            config = yaml.safe_load(config_file)
            include_accepted_and_falsepositives = config['INCLUDE_ACCEPTED_AND_FP']
            logging.debug('Include AcceptedRisk and FalsePositive vulnerabilities in the count: %s'
                          % include_accepted_and_falsepositives)
        except Exception as file_exception:
            logging.critical('Something went wrong while loading config: %s' % file_exception,
                             exc_info=logging.getLogger().getEffectiveLevel() == logging.DEBUG)

    main()
