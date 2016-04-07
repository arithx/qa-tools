qa-tools
========

A collection of tools primarily focused on extending current OpenStack tooling.

subunit-verify
--------------

Takes a list of tests that were ran through tempest and a subunit stream and
outputs a table showing the stats of the run for those specific tests.

Detects both failures at the fixture level as well as tests not being ran
(usually occurs due to issues with test loading or the selection regex).

::

    subunit-verify [-s/--subunit] [-t/--test-list] [-n/--non-subunit-name] [-o/--output-file]

When not given an output file it dumps a simplified table to the screen. With
an output table specified it dumps a JSON list of each test and it's status of
the following format:

::

    {
        "test_name": {
            "status": enum("Pass", "Skip", "Error, "Fail", "Fixture Failure", "Not Ran"),
            "message": "Error message if applicable"
        }
    }


subunit-parser
--------------

Outputs all HTTP calls, in the order they were made, for a given test.

::

    subunit-describe-calls [-s/--subunit] [-n/--non-subunit-name] [-o/--output-file]

The format of the output file is in JSON and follows the following structure:

::

    {
        "full_test_name[with_id_and_tags]": [
            {
                "name": "The ClassName.MethodName that made the call",
                "verb": "HTTP Verb",
                "service": "Name of the service",
                "url": "A shortened version of the URL called"
            }
        ]
    }


test-loader
-----------

Takes a given list of tests, updates the test names to properly add idempotent
id's and tags, and runs subunit-verify on the results.

NOTE: This requires the refstack-client tool. Please install it from
http://github.com/openstack/refstack-client before using test-loader

::

    test-loader [-t/--test-list] [-p/--tempest-path] [-c/--concurrency] [-o/--output-file]
