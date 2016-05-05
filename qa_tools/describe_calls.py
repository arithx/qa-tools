#!/usr/bin/python
#

# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import argparse
import collections
import io
import json
import os
import re

import subunit
import testtools


class UrlParser(testtools.TestResult):
    uuid_re = re.compile(r'(^|[^0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-'
                         '[0-9a-f]{4}-[0-9a-f]{12}([^0-9a-f]|$)')
    id_re = re.compile(r'(^|[^0-9a-z])[0-9a-z]{8}[0-9a-z]{4}[0-9a-z]{4}'
                       '[0-9a-z]{4}[0-9a-z]{12}([^0-9a-z]|$)')
    ip_re = re.compile(r'(^|[^0-9])[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]'
                       '{1,3}([^0-9]|$)')
    url_re = re.compile(r'.*INFO.*Request \((?P<name>.*)\): (?P<code>[\d]{3}) '
                        '(?P<verb>\w*) (?P<url>.*) .*')
    port_re = re.compile(r'.*:(?P<port>\d+).*')
    path_re = re.compile(r'http[s]?://[^/]*/(?P<path>.*)')
    request_re = re.compile(r'.* Request - Headers: (?P<headers>.*)')
    response_re = re.compile(r'.* Response - Headers: (?P<headers>.*)')
    body_re = re.compile(r'.*Body: (?P<body>.*)')

    # Based on kilo defaults:
    # http://docs.openstack.org/kilo/config-reference/
    # content/firewalls-default-ports.html
    services = {
        "8776": "Block Storage",
        "8774": "Nova",
        "8773": "Nova-API", "8775": "Nova-API",
        "8386": "Sahara",
        "35357": "Keystone", "5000": "Keystone",
        "9292": "Glance", "9191": "Glance",
        "9696": "Neutron",
        "6000": "Swift", "6001": "Swift", "6002": "Swift",
        "8004": "Heat", "8000": "Heat", "8003": "Heat",
        "8777": "Ceilometer",
        "80": "Horizon",
        "8080": "Swift",
        "443": "SSL",
        "873": "rsync",
        "3260": "iSCSI",
        "3306": "MySQL",
        "5672": "AMQP"}

    def __init__(self, services=None):
        super(UrlParser, self).__init__()
        self.test_logs = {}
        self.services = services or self.services

    def addSuccess(self, test, details=None):
        output = test.shortDescription() or test.id()
        calls = self.parse_details(details)
        self.test_logs.update({output: calls})

    def addSkip(self, test, err, details=None):
        output = test.shortDescription() or test.id()
        calls = self.parse_details(details)
        self.test_logs.update({output: calls})

    def addError(self, test, err, details=None):
        output = test.shortDescription() or test.id()
        calls = self.parse_details(details)
        self.test_logs.update({output: calls})

    def addFailure(self, test, err, details=None):
        output = test.shortDescription() or test.id()
        calls = self.parse_details(details)
        self.test_logs.update({output: calls})

    def stopTestRun(self):
        super(UrlParser, self).stopTestRun()

    def startTestRun(self):
        super(UrlParser, self).startTestRun()

    def parse_details(self, details):
        if details is None:
            return

        calls = []
        for _, detail in details.items():
            in_request = False
            in_response = False
            current_call = {}
            for line in detail.as_text().split("\n"):
                url_match = self.url_re.match(line)
                request_match = self.request_re.match(line)
                response_match = self.response_re.match(line)
                body_match = self.body_re.match(line)

                if url_match is not None:
                    if current_call != {}:
                        calls.append(current_call.copy())
                        current_call = {}
                        in_request, in_response = False, False
                    current_call.update({
                        "name": url_match.group("name"),
                        "verb": url_match.group("verb"),
                        "status_code": url_match.group("code"),
                        "service": self.get_service(url_match.group("url")),
                        "url": self.url_path(url_match.group("url"))})
                elif request_match is not None:
                    in_request, in_response = True, False
                    current_call.update({"request_headers": request_match.group(
                        "headers")})
                elif in_request and body_match is not None:
                    in_request = False
                    current_call.update({"request_body": body_match.group("body")})
                elif response_match is not None:
                    in_request, in_response = False, True
                    current_call.update({"response_headers": response_match.group(
                        "headers")})
                elif in_response and body_match is not None:
                    in_response = False
                    current_call.update({"response_body": body_match.group("body")})
            if current_call != {}:
                calls.append(current_call.copy())

        return calls

    def get_service(self, url):
        match = self.port_re.match(url)
        if match is not None:
            return self.services.get(match.group("port"), "Unknown")
        return "Unknown"

    def url_path(self, url):
        match = self.path_re.match(url)
        if match is not None:
            path = match.group("path")
            path = self.uuid_re.sub(r'\1<uuid>\2', path)
            path = self.ip_re.sub(r'\1<ip>\2', path)
            path = self.id_re.sub(r'\1<id>\2', path)
            return path
        return url


class FileAccumulator(testtools.StreamResult):

    def __init__(self, non_subunit_name='pythonlogging'):
        super(FileAccumulator, self).__init__()
        self.route_codes = collections.defaultdict(io.BytesIO)
        self.non_subunit_name = non_subunit_name

    def status(self, **kwargs):
        if kwargs.get('file_name') != self.non_subunit_name:
            return
        file_bytes = kwargs.get('file_bytes')
        if not file_bytes:
            return
        route_code = kwargs.get('route_code')
        stream = self.route_codes[route_code]
        stream.write(file_bytes)


class ArgumentParser(argparse.ArgumentParser):
    def __init__(self):
        desc = "Outputs all HTTP calls a given test made that were logged."
        usage_string = """
            subunit-describe-calls [-s/--subunit] [-n/--non-subunit-name]
                                   [-o/--output-file] [-p/--ports]
        """

        super(ArgumentParser, self).__init__(
            usage=usage_string, description=desc)

        self.prog = "Argument Parser"

        self.add_argument(
            "-s", "--subunit", metavar="<subunit file>", required=True,
            default=None, help="The path to the subunit output file.")

        self.add_argument(
            "-n", "--non-subunit-name", metavar="<non subunit name>",
            default="pythonlogging",
            help="The name used in subunit to describe the file contents.")

        self.add_argument(
            "-o", "--output-file", metavar="<output file>", default=None,
            help="The output file name for the json.", required=True)

        self.add_argument(
            "-p", "--ports", metavar="<ports file>", default=None,
            help="A JSON file describing the ports for each service.")


def parse(subunit_file, non_subunit_name, ports):
    if ports is not None and os.path.exists(ports):
        ports = json.loads(open(ports).read())

    url_parser = UrlParser(ports)
    stream = open(subunit_file, 'rb')
    suite = subunit.ByteStreamToStreamResult(
        stream, non_subunit_name=non_subunit_name)
    result = testtools.StreamToExtendedDecorator(url_parser)
    accumulator = FileAccumulator(non_subunit_name)
    result = testtools.StreamResultRouter(result)
    result.add_rule(accumulator, 'test_id', test_id=None)
    result.startTestRun()
    suite.run(result)

    for bytes_io in accumulator.route_codes.values():  # v1 processing
        bytes_io.seek(0)
        suite = subunit.ProtocolTestCase(bytes_io)
        suite.run(url_parser)
    result.stopTestRun()

    return url_parser


def output(url_parser, output_file):
    with open(output_file, "w") as outfile:
        outfile.write(json.dumps(url_parser.test_logs))


def entry_point():
    cl_args = ArgumentParser().parse_args()
    parser = parse(cl_args.subunit, cl_args.non_subunit_name, cl_args.ports)
    output(parser, cl_args.output_file)
