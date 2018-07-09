import os

import argparse
import json
import requests

from subprocess import check_output
from modules import group, matrix, util, software

def main():
    parser = argparse.ArgumentParser(description="Update ATT&CK matrices and kick off the publish process")
    parser.add_argument('-r', '--refresh', action='store_true', help='Pull down fresh STIX data from GitHub')
    parser.add_argument('-p', '--publish', action='store_true', help='Push output/ directory to GitHub pages')
    args = parser.parse_args()
    
    DIR_NAME = 'stix'
    
    with open('./settings.json', 'r') as f:
        settings = json.loads(f.read())
        DOMAINS = settings['domains']
        DEVELOPMENT_MODE = settings['development']
        DOMAIN_ALIASES = settings['domain_aliases']
        NAVIGATION_MENU = settings['navigation_menu']

    with open('./attack-theme/templates/base.html', 'r') as f:
        base_template = f.read()
        base_template = base_template.split("{% set active_page = active_page|default('index') -%}\n")[-1]
        jinja_settings = '{% set DEVELOPMENT = "' + DEVELOPMENT_MODE + '" %}\n'
        jinja_settings += "{% set NAVIGATION_MENU = [\n"
        for attributes in NAVIGATION_MENU:
            jinja_settings += "\t("
            jinja_settings += ', '.join('"{0}"'.format(attr) for attr in attributes)
            jinja_settings += "),\n"
        jinja_settings += "] -%}\n"
        jinja_settings += "{% set DOMAINS = ["
        for domain in DOMAIN_ALIASES:
            jinja_settings += '("{0}"),'.format(domain)
        jinja_settings = jinja_settings[:-1]
        jinja_settings += "] -%}\n"
        jinja_settings += "{% set active_page = active_page|default('index') -%}\n"

    with open('./attack-theme/templates/base.html', 'w+') as f:
        f.write(jinja_settings + base_template)

            # {% set NAVIGATION_MENU="" %} \
            # {% set DOMAINS = "" %}".format(DEVELOPMENT_MODE)

    IS_STIX_LOCAL = True
    for domain in DOMAINS:
        if not (os.path.isfile('{0}/{1}.json'.format(DIR_NAME, domain))):
            IS_STIX_LOCAL = False

   
    if (args.refresh or not os.path.isdir(DIR_NAME) or not IS_STIX_LOCAL):
        print('{0} Retrieving STIX data from GitHub'.format(util.timestamp()))

        if (not os.path.isdir(DIR_NAME)):
            os.mkdir(DIR_NAME)

        for domain in DOMAINS:
            r = requests.get('https://raw.githubusercontent.com/mitre/cti/master/{0}/{0}.json'.format(domain), verify=False)
            with open('./stix/{0}.json'.format(domain), 'w+') as f:
                f.write(json.dumps(r.json()))
    else:
        print('{0} Loading STIX data from disk'.format(util.timestamp()))


    group.generate()
    software.generate()
    returned_out = check_output("pelican content", shell=True)
    print(returned_out)
    group.updateLinkSections()
    software.updateLinkSections()
    #nav.generate()

    matrix.generate(DOMAINS)
    

if __name__ == "__main__":
    main()
