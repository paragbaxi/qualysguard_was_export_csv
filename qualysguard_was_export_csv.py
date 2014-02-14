from __future__ import print_function

__author__ = 'Parag Baxi'


import argparse
import csv
import datetime
import logging
import os
import qualysapi
import sys
import unicodedata

from collections import defaultdict
from lxml import etree, objectify
from progressbar import AnimatedMarker, ProgressBar, SimpleProgress


def compare_webapps(list1, list2):
    """ Return list of matching dictionaries from two lists of dictionaries.
    """
    check = set([(d['name'], d['id']) for d in list2])
    return [d for d in list1 if (d['name'], d['id']) in check]


def count_apps(tag=None):
    """Count applicable apps from QualysGuard.
    """
    uri = '/count/was/webapp'
    data = None
    if tag:
        data = '''
        <ServiceRequest>
            <filters>
                <Criteria field="tags.name" operator="EQUALS">%s</Criteria>
                <Criteria field="createdDate" operator="GREATER">2000-02-21T00:00:00Z</Criteria>
            </filters>
        </ServiceRequest>''' % tag
    xml = qgc.request(uri, data)
    root = objectify.fromstring(xml)
    return int(root.count.text)


def download_apps(tag=None):
    """Download apps from QualysGuard.
    """
    # Count applicable apps.
    app_count = count_apps(tag)
    last_record = '0'
    apps = []
    print('Downloading applications:')
    # Show progress bar.
    pbar = ProgressBar(widgets=[SimpleProgress()], maxval=app_count).start()
    while True:
        # Get list of web apps.
        query_uri = '/search/was/webapp'
        data = '''
        <ServiceRequest>
            <filters>
                <Criteria field="createdDate" operator="GREATER">2000-02-21T00:00:00Z</Criteria>
                <Criteria field="id" operator="GREATER">%s</Criteria>
            </filters>
            <preferences>
                <limitResults>1000</limitResults>
            </preferences>
        </ServiceRequest>''' % (last_record)
        if tag:
            # Insert additional criteria for tag after '<filters>'.
            new_criteria_position = data.find('<filters>\n') + 18
            data = data[:new_criteria_position] + \
                   '<Criteria field="tags.name" operator="EQUALS">%s</Criteria>' % (c_args.tag) + \
                   data[new_criteria_position:]
        logging.debug('data = \n%s' % data)
        search_apps = qgc.request(query_uri, data)
        # Parse list of web apps to associate each web app id with web app name.
        tree = objectify.fromstring(search_apps)
        for webapp in tree.data.WebApp:
            app = defaultdict(str)
            app_name = webapp.name.text
            # App name may be in unicode.
            if isinstance(app_name, unicode):
                # Decode to string.
                app_name = unicodedata.normalize('NFKD', app_name).encode('ascii', 'ignore')
            app['name'] = app_name
            app['id'] = webapp.id.text
            apps.append(app)
            pbar.update(len(apps))
        if tree.hasMoreRecords.text == 'true':
            last_record = tree.lastId.text
        else:
            break
    print
    '\n'
    logging.info('apps = %s' % (apps))
    return apps

#
#  Begin
#
# Declare the command line flags/options we want to allow.
parser = argparse.ArgumentParser(
    description='Generate CSV from webapps that were recently scanned by QualysGuard WAS.')
parser.add_argument('-a', '--override_all_apps',
                    help='Generate report for all webapps. Automatically selected for first run.')
parser.add_argument('-D', '--override_date',
                    help='Search scans from DATE_OVERRIDE date (YYYY-MM-DD).')
parser.add_argument('-d', '--days',
                    help='Search scans back DAYS day(s) from today midnight.')
parser.add_argument('-o', '--output_filename',
                    default='qualysguard_was.csv',
                    help='Filename of outputted CSV. (Default = qualysguard_was.csv)')
parser.add_argument('-r', '--resume',
                    default=1,
                    help='Search scans ahead RESUME days from last previous successfully imported date. (Default = 1)')
parser.add_argument('-t', '--tag',
                    default=1,
                    help='Scope import to webapps with TAG tag. Overrides OVERRIDE_ALL_APPS.')
parser.add_argument('-v', '--verbose',
                    action='store_true',
                    help='Outputs additional information to log.')
parser.add_argument('--config',
                    help='Configuration for Qualys connector.')
# Parse arguments.
c_args = parser.parse_args()# Create log directory.
# Create log directory.
PATH_LOG = 'log'
if not os.path.exists(PATH_LOG):
    os.makedirs(PATH_LOG)
# Set log options.
LOG_FILENAME = '%s/%s-%s.log' % (PATH_LOG,
                                 __file__,
                                 datetime.datetime.now().strftime('%Y-%m-%d.%H-%M-%S'))
# Make a global logging object.
logger = logging.getLogger()
if c_args.verbose:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.ERROR)
# This handler writes everything to a file.
logger_file = logging.FileHandler(LOG_FILENAME)
logger_file.setFormatter(logging.Formatter("%(asctime)s %(name)-12s %(levelname)s %(funcName)s %(lineno)d %(message)s"))
logger_file.setLevel(logging.INFO)
if c_args.verbose:
    logger_file.setLevel(logging.DEBUG)
logger.addHandler(logger_file)
# This handler prints to screen.
logger_console = logging.StreamHandler(sys.stdout)
logger.addHandler(logger_console)
# Set defaults.
check_all_webapps = False
check_from_date = False
# How many days back should I check from?
if c_args.override_all_apps:
    # Check all webapps.
    check_all_webapps = True
elif c_args.days:
    # Go back c_args.days days.
    check_from_date = (datetime.date.today() - datetime.timedelta(days=int(c_args.days))).strftime("%Y-%m-%d")
elif c_args.override_date:
    # Go back to c_args.override_date date.
    check_from_date = c_args.override_date
elif c_args.resume:
    if os.path.exists('data.txt'):
        # Check data.txt for last successful import.
        with open('data.txt', 'r+') as f:
            last_successful_date = f.readline()
            check_from_date = last_successful_date + c_args.resume
else:
    # First run. Check all webapps.
    check_all_webapps = True
# Configure Qualys API connector.
if c_args.config:
    qgc = qualysapi.connect(c_args.config)
else:
    qgc = qualysapi.connect()
# Which webapps am I pulling?
if check_all_webapps or c_args.tag:
    # Download all apps, scope to tag if applicable.
    apps = download_apps(tag=c_args.tag)
if check_from_date:
    # Download only webapps that were successfully scanned from check_from_date.
    # Pull scan list.
    data = '''
    <ServiceRequest>
       <filters>
           <Criteria field="status" operator="EQUALS">FINISHED</Criteria>
           <Criteria field="launchedDate" operator="GREATER">%sT00:00:00Z</Criteria>
        </filters>
    </ServiceRequest>''' % check_from_date
    # TODO processsed scans only.
    criteria_processed_scans = '<Criteria field="resultsStatus" operator="EQUALS">SUCCESSFUL</Criteria>'
    # Call QualysGuard API.
    scan_xml_list = qgc.request('/search/was/wasscan', data)
    # Parse XML.
    root = objectify.fromstring(scan_xml_list)
    scanned_apps = set()
    for was_scan in root.data.WasScan:
        app = defaultdict(str)
        app_name = was_scan.target.webApp.name.text
        # App name may be in unicode.
        if isinstance(app_name, unicode):
            # Decode to string.
            app_name = unicodedata.normalize('NFKD', app_name).encode('ascii', 'ignore')
        app['name'] = app_name
        app['id'] = was_scan.target.webApp.id.text
        scanned_apps.add(app)
        # Dedupe webapps in case a webapp was scanned more than once since check_from_date.
    scanned_apps = list(scanned_apps)
    # Remove webapps that don't have requested tag (if applicable).
    if c_args.tag:
        # Diff from list of apps scoped to tag.
        apps = compare_webapps(scanned_apps, apps)
# Launch webapp report against applicable webapps.
uri = '/create/was/report'
data = '''
<ServiceRequest>
  <data>
    <Report>
      <name><![CDATA[Export]]></name>
      <description><![CDATA[CSV report for integration.]]></description>
      <format>XML</format>
      <type>WAS_WEBAPP_REPORT</type>
      <config>
        <webAppReport>
          <target>
            <webapps>'''
for app in apps:
    data += '''
                <WebApp>
                    <id>%s</id>
                </WebApp>''' % str(app['id'])
data += '''
            </webapps>
          </target>
          <display>
            <contents>
              <WebAppReportContent>RESULTS</WebAppReportContent>
              <WebAppReportContent>INDIVIDUAL_RECORDS</WebAppReportContent>
            </contents>
          </display>
        </webAppReport>
      </config>
    </Report>
  </data>
</ServiceRequest>'''
# Call API to create webapp report.
print('Generating webapp report...')
xml = qgc.request('/create/was/report/', data)
# Parse webapp report id.
root = objectify.fromstring(xml)
report_id = root.data.Report.id.text
# Download report.
print('Downloading webapp report...')
xml = qgc.request('/download/was/report/%s' % report_id)
# Parse XML for severity levels.
root = objectify.fromstring(xml)
qids = defaultdict(lambda: defaultdict(str))
for qid in root.GLOSSARY.QID_LIST.QID:
    qids[qid.QID.text] = {'severity': qid.SEVERITY.text, 'cwe': qid.CWE.text, 'title': qid.TITLE.text}
# Parse XML for vulns.
with open(c_args.output_filename, 'wb') as csvfile:
    print('Writing CSV to %s...' % c_args.output_filename)
    csv_writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
    for webapp in root.RESULTS.WEB_APPLICATION:
        try:
            for vuln in webapp.VULNERABILITY_LIST.VULNERABILITY:
                csv_writer.writerow([vuln.ID.text, vuln.QID.text, qids[vuln.QID.text]['severity'],
                                    qids[vuln.QID.text]['cwe'], qids[vuln.QID.text]['title'], vuln.STATUS.text,
                                    vuln.URL.text, vuln.FIRST_TIME_DETECTED.text, vuln.LAST_TIME_DETECTED.text,
                                    vuln.IGNORED.text])
        except AttributeError as e:
            # No vulns in this webapp.
            logging.debug('No vulns in %s.' % webapp.NAME.text)
            pass
