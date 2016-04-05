import argparse
import os
import subprocess

from refstack_client.list_parser import TestListParser
from qa_tools import subunit_verify


def normalize_test_list(tempest_path, test_list):
    """ Parses the test list and adds ids & tags """
    return TestListParser(tempest_path).get_normalized_test_list(test_list)


def build_run_options(regex=None, concurrency=None, load_list=None):
    command = []
    command.append("testr")
    command.append("run")

    if regex is not None:
        command.append(regex)

    if concurrency is not None:
        command.append("--concurrency")
        command.append(concurrency)

    if load_list is not None:
        command.append("--load-list")
        command.append(load_list)

    command.append("--subunit")
    return command


def build_trace_options():
    command = []
    command.append("subunit-trace")
    command.append("--no-failure-debug")
    command.append("-f")
    return command


def run_piped_commands(cmd_a, cmd_b, cwd):
    proc_a = subprocess.Popen(cmd_a, stdout=subprocess.PIPE, cwd=cwd)
    proc_b = subprocess.Popen(
        cmd_b, stdin=proc_a.stdout, stdout=subprocess.PIPE, cwd=cwd)
    proc_a.stdout.close()
    return proc_b.communicate()[0]


def run_tempest(tempest_path, concurrency, test_list):
    run_options = build_run_options(
        concurrency=concurrency, load_list=test_list)
    trace_options = build_trace_options()
    run_piped_commands(run_options, trace_options, tempest_path)


def get_subunit_file(tempest_path):
    return os.path.join(
        tempest_path, ".testrepository", str(int(open(os.path.join(
            tempest_path, ".testrepository", "next-stream")).read().strip(
                "\n")) - 1))


def verify_run(tempest_path, test_list, output_file):
    subunit_file = get_subunit_file(tempest_path)
    subunit_verify.verify_subunit(
        subunit_file, test_list, "stdout", output_file)


class ArgumentParser(argparse.ArgumentParser):
  def __init__(self):
    desc = "Runs tempest from a list of tests and verifies all tests were ran."
    usage_string = """
        test-loader [-t/--test-list] [-p/--tempest-path]
            [-c/--concurrency] [-o/--output-file]
    """

    super(ArgumentParser, self).__init__(
        usage=usage_string, description=desc)

    self.prog = "Argument Parser"

    self.add_argument(
        "-t", "--test-list", metavar="<test list file>", default=None,
        help="The path to the test list file to be ran.")

    self.add_argument(
        "-p", "--tempest-path", metavar="<path to tempest>",
        default="/opt/stack/new/tempest", help="The path to tempest.")

    self.add_argument(
        "-c", "--concurrency", default=None, metavar="<concurrency>",
        help="Enables concurrency and specifies worker count", type=int)

    self.add_argument(
        "-o", "--output-file", metavar="<output file>", default=None,
        help="The output file name for the json.")


def entry_point():
    cl_args = ArgumentParser().parse_args()
    test_list = normalize_test_list(cl_args.tempest_path, cl_args.test_list)
    run_tempest(cl_args.tempest_path, cl_args.concurrency, test_list)
    verify_run(cl_args.tempest_path, test_list, cl_args.output_file)
