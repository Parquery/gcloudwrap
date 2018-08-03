#!/usr/bin/env python3
"""
benchmarks the Google client API against CLI.
"""
import os
import subprocess
import time
import uuid

import gcloudwrap

TEST_GCLOUDWRAP_SERVICE_ACCOUNT = os.environ.get('TEST_GCLOUDWRAP_SERVICE_ACCOUNT', None)
TEST_GCLOUDWRAP_PREFIX = os.environ.get('TEST_GCLOUDWRAP_PREFIX', 'test-gcloudwrap')


def benchmark_instance_exists() -> None:
    """
    benchmarks multiple calls to check with instance.exists().

    :return:
    """
    gce = gcloudwrap.Gce()

    instance = "{}-{}".format(TEST_GCLOUDWRAP_PREFIX, uuid.uuid4())

    try:
        print("Creating the instance {} ...".format(instance))
        gce.instances.insert(name=instance, machine_type='f1-micro', service_account=TEST_GCLOUDWRAP_SERVICE_ACCOUNT)

        print("instances().exists: running client 5x...")
        start = time.time()
        for _ in range(5):
            gce.instances.exists(name=instance)

        duration_us = time.time() - start

        print("instances().exists: running CLI 5x...")
        start = time.time()
        for _ in range(5):
            # yapf: disable
            subprocess.check_call(
                ['gcloud', 'compute', 'instances', 'list', '--filter', 'name~^{}$'.format(instance)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # yapf: enable

        duration_cli = time.time() - start

        print("instance exists comparison with CLI: {:.2f}s (gcloudwrap), {:.2f}s (CLI)".format(
            duration_us, duration_cli))

    finally:
        if gce.instances.exists(name=instance):
            print("Deleting the instance {} ...".format(instance))
            gce.instances.delete(instance=instance)


def main() -> None:
    """"
    Main routine
    """
    benchmark_instance_exists()


if __name__ == "__main__":
    main()
