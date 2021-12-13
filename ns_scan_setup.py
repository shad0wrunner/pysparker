from base64 import b64encode
import json
import logging
from ns_scan_runner import parse_parameters, norm_url
import requests
import yaml


def get_api_token(user_id, user_token):
    """ Builds base64 API token """
    logging.info('Building API Token')
    string_to_encode = user_id + ':' + user_token
    api_token = b64encode(string_to_encode.encode()).decode()
    logging.debug('API token: %s' % api_token)
    return api_token


def configure_scan_policy(api_token, json_file):
    """ Configuring Scanning policy based on an external JSON file with settings """
    api_handle = 'http://' + config['API_HOST'] + '/api/1.0/scanpolicies/new'
    headers = {
        'Authorization': "Basic " + api_token,
        'User-Agent': "NetFish",
        'Host': config['API_HOST'],
        'Content-Type': "application/json"
    }

    logging.info('Reading Policy file')
    with open(json_file) as policy:
        scan_policy = policy.read()

    # getting policy name
    scan_policy_name = json.loads(scan_policy)['Name']

    logging.info('Creating New Scanning Policy')
    json_response = requests.request("POST", api_handle, data=scan_policy, headers=headers)

    # if Policy with the same name exists - assume that user wants to re-use it => return its ID
    if json_response.status_code != 201:
        logging.error(json_response.text)
        logging.warning('Trying to obtain existing Policy by name')
        get_policy_api_handle = 'http://' + config['API_HOST'] + '/api/1.0/scanpolicies/get'
        json_response = requests.request("GET", get_policy_api_handle, params={'name': scan_policy_name},
                                         headers=headers)

    scan_policy_id = json.loads(json_response.text)['Id']

    logging.debug('Scan Policy ID: %s' % scan_policy_id)
    return scan_policy_id


def configure_scan_profile(api_token, json_file, policy_id=""):
    """ Configuring Scanning profile based on an external JSON file with settings """
    api_handle = 'http://' + config['API_HOST'] + "/api/1.0/scanprofiles/new"
    headers = {
        'Authorization': "Basic " + api_token,
        'User-Agent': "Netfish",
        'Host': config['API_HOST'],
        'Content-Type': "application/json"
    }

    logging.info('Reading Profile file')
    with open(json_file) as profile:
        scan_profile = profile.read()

    # setting policy id to the policy created previously
    scan_profile = json.loads(scan_profile)
    scan_profile['PolicyId'] = policy_id
    scan_profile_name = scan_profile['ProfileName']
    scan_profile = json.dumps(scan_profile)

    logging.info('Creating New Scanning Profile')
    json_response = requests.request("POST", api_handle, data=scan_profile, headers=headers)

    # if Profile with the same name exists - assume that user wants to re-use it => return its ID
    if json_response.status_code != 201:
        logging.error(json_response.text)
        logging.warning('Trying to obtain existing Profile by name')
        get_profile_api_handle = 'http://' + config['API_HOST'] + '/api/1.0/scanprofiles/get'
        json_response = requests.request("GET", get_profile_api_handle, params={'name': scan_profile_name},
                                         headers=headers)

    scan_profile_id = json.loads(json_response.text)['ProfileId']

    logging.debug('Scan Profile ID and name: %s - %s' % (scan_profile_id, scan_profile_name))
    return scan_profile_id, scan_profile_name


def get_license_id(api_token):
    """ Gets license ID to create a website """

    api_handle = 'http://' + config['API_HOST'] + '/api/1.0/account/license'
    headers = {
        'Authorization': "Basic " + api_token,
        'User-Agent': "Netfish",
        'Host': config['API_HOST']
    }

    logging.info('Getting License ID')
    json_response = requests.request("GET", api_handle, headers=headers, verify=verify_ssl)
    if json_response.status_code == 401:
        raise Exception('Incorrect API authorization token')

    licenses = json.loads(json_response.text)['Licenses']  # getting Licenses sub-node
    license_id = dict(licenses[0])['Id']

    logging.debug('License ID: %s' % license_id)
    return license_id


def configure_website(api_token):
    """ Configuring Website to scan  """

    website_created = False

    # getting license id as it is needed to create a website
    license_id = get_license_id(api_token)
    api_handle = 'http://' + config['API_HOST'] + '/api/1.0/websites/new'
    list_websites_handle = 'http://' + config['API_HOST'] + '/api/1.0/websites/list'
    headers = {
        'Authorization': "Basic " + api_token,
        'User-Agent': "Netfish",
        'Host': config['API_HOST'],
        'Content-Type': "application/json"
    }

    # Building JSON request body to create new website
    website_json = \
        {"RootUrl": config['SCAN_URL'],
         "Name": config['WEBSITE_NAME'],
         "LicenseType": "Subscription",
         "TechnicalContactEmail": config['CONTACT_EMAIL'],
         "SubscriptionBasedProductLicenseId": license_id}

    logging.info('Creating New Website')
    logging.debug('Fetching websites list')
    websites_list = json.loads(
        requests.request("GET", list_websites_handle, params={"pageSize": 200},
                         headers=headers, verify=verify_ssl).text)['List']

    logging.debug('Checking website or URL doesn\'t exist')
    found_website = next((item for item in websites_list if item["Name"] == config['WEBSITE_NAME']), False)
    found_url = next((item for item in websites_list if
                      norm_url(item["RootUrl"]) == norm_url(config['SCAN_URL'])), False)

    if found_website or found_url:
        logging.warning('Target %s already exist(s)' %
                        (config['WEBSITE_NAME'] * (found_website is not False) + ' and ' *
                         ((found_website and found_url) is not False) +
                         ('URL ' + norm_url(config['SCAN_URL'])) * (found_url is not False)))
    else:
        json_response = requests.request("POST", api_handle, data=json.dumps(website_json), headers=headers,
                                         verify=verify_ssl)

        if json_response.status_code != 201:
            logging.error('Error while creating website: ' + json_response.text)
        else:
            website_created = True
            logging.debug('Website created')

    return website_created


def main():
    try:
        api_token = get_api_token(config['USERID'], config['TOKEN'])
        policy_id = configure_scan_policy(api_token, config['SCAN_POLICY_FILE'])
        configure_scan_profile(api_token, config['SCAN_PROFILE_FILE'], policy_id)
        configure_website(api_token)  # setting up new Website if it doesn't exist

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
    logging.basicConfig(level=log_level, format=log_format)

    logging.info('Starting main module')
    logging.debug('Verifying invalid SSL certificates: %s' % verify_ssl)
    logging.debug('Loading config file')
    with open(parameters[0], 'r') as config_file:
        try:
            config = yaml.safe_load(config_file)
        except Exception as file_exception:
            logging.critical('Something went wrong while loading config: %s' % file_exception,
                             exc_info=logging.getLogger().getEffectiveLevel() == logging.DEBUG)

    main()
