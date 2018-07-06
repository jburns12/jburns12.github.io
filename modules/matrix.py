import json
import os
import requests
import sys
import urllib3

from .util import timestamp

# suppress InsecureRequestWarning: Unverified HTTPS request is being made
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_max_length(matrix):
    max_len = 0
    for key in matrix:
        if len(matrix[key]) > max_len:
            max_len = len(matrix[key])
    return max_len

def load_attack_patterns(domain, delimiter):
    matrix = {}

    with open(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'stix/{0}.json'.format(domain)))) as f:
        data = json.loads(f.read())
    
    for obj in data['objects']:
        if obj['type'] == 'attack-pattern':
            if len(obj['kill_chain_phases']):
                for elem in obj['kill_chain_phases']:
                    try:
                        matrix[elem['phase_name']].append('{0}{1}{2}'.format(obj['name'], delimiter, obj['external_references'][0]['url']))
                    except:
                        matrix[elem['phase_name']] = []
                        matrix[elem['phase_name']].append('{0}{1}{2}'.format(obj['name'], delimiter, obj['external_references'][0]['url']))
    
    return matrix

def build_html(matrix, delimiter, domain):
    print('{0} Constructing {1} HTML matrix'.format(timestamp(), domain))
    tacticsData = requests.get('https://raw.githubusercontent.com/mitre/attack-navigator/develop/nav-app/src/assets/tacticsData.json', verify=False).json()

    if domain == 'enterprise-attack':
        tactics = tacticsData['enterprise_tactics']['tactics']
        html =  """<table class='table table-bordered'>
                    <thead class='bg-orange color-white'>
                        <tr>
                """

        for tactic in tactics:
            if not tactic['tactic'] == 'command-and-control':
                html += '<th scope=\'col\'>{0}</th>'.format(tactic['tactic'].title().replace('-', ' '))
            else:
                html += '<th scope=\'col\'>Command and Control</th>'

        html += """
                        </tr>
                    </thead>
                    <tbody>
                """
    elif domain == 'pre-attack':
        tactics = tacticsData['pre_attack_tactics']['tactics']
        html =  """<table class='table table-bordered'>
                    <thead class='bg-orange color-white'>
                        <tr>
                """

        for tactic in tactics:
            html += '<th scope\'col\'>{0}</th>'.format(tactic['tactic'].title().replace('-', ' '))

        html = html.replace('Opsec', 'OPSEC')
        html += """        </tr>
                    </thead>
                    <tbody>
                """
    elif domain == 'mobile-attack':
        tactics = tacticsData['mobile_tactics']['tactics']
        html =  """<table class='table table-bordered'>
                    <thead class='bg-orange color-white'>
                        <tr>
                """

        for tactic in tactics:
            if not tactic['tactic'] == 'command-and-control':
                    html += '<th scope=\'col\'>{0}</th>'.format(tactic['tactic'].title().replace('-', ' ').replace('Via', 'via'))
            else:
                html += '<th scope=\'col\'>Command and Control</th>'

        html += """        </tr>
                    </thead>
                    <tbody>
                """

    ctr = 0
    max_len = get_max_length(matrix)
    for ctr in range(0, max_len):
        table_row = '<tr>'
        for obj in tactics:
            if not obj == 'launch' and not obj =='compromise':
                matrix[obj['tactic']].sort()
                if (ctr < len(matrix[obj['tactic']])):
                    technique = matrix[obj['tactic']][ctr].split(delimiter)[0]
                    url = matrix[obj['tactic']][ctr].split(delimiter)[1]
                    table_row += '<td><a href="{0}">{1}</a></td>'.format(url, technique)
                else:
                    table_row += '<td></td>'
        table_row += '</tr>'
        html += table_row
    html += "</tbody></table>"

    return html

def create_matrix(html, domain):
    if domain == 'enterprise-attack':
        # create index page when parsing enterprise-attack.json, too
        with open(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'attack-theme/templates/index.bak')), 'r') as f:
            file_data = f.read()
    
        file_data = file_data.replace('$MATRIX', html)

        with open(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'attack-theme/templates/index.html')), 'w+',  encoding='utf8') as f:
            f.write(file_data)
    
    with open(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'attack-theme/templates/matrix-{0}.bak'.format(domain))), 'r') as f:
        file_data = f.read()
    
    file_data = file_data.replace('$MATRIX', html)

    with open(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'attack-theme/templates/matrix-{0}.html').format(domain)), 'w+', encoding='utf8') as f:
        f.write(file_data)

def generate(domains):
    delimiter = "|||" # This is arbitrary, feel free to change in production. It only needs to be changed here.

    for domain in domains:
        matrix = load_attack_patterns(domain, delimiter)
        html = build_html(matrix=matrix, delimiter=delimiter, domain=domain)
        create_matrix(html, domain)