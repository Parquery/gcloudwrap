#!/usr/bin/env python3

# pylint: disable=missing-docstring
# pylint: disable=protected-access

import pathlib
import tempfile
import unittest

import gcloudwrap


class TestGcloudwrap(unittest.TestCase):
    def test_disk_user_from_url(self):
        url = 'https://www.googleapis.com/compute/v1/projects/some-project/zones/europe-west1-c/instances/some-inst'
        disk_user = gcloudwrap._disk_user_from_url(url=url)
        self.assertEqual(disk_user.project, "some-project")
        self.assertEqual(disk_user.zone, "europe-west1-c")
        self.assertEqual(disk_user.instance, "some-inst")

    def test_parse_machine_type(self):
        url = 'https://www.googleapis.com/compute/v1/projects/some-project-1984/' \
              'zones/europe-west1-c/machineTypes/n1-standard-1'

        machine_type = gcloudwrap._parse_machine_type(url=url)
        self.assertEqual(machine_type, "n1-standard-1")

        url = 'https://www.googleapis.com/compute/v1/projects/some-project-1984/' \
              'zones/europe-west1-c/machineTypes/custom-8-1024'
        machine_type = gcloudwrap._parse_machine_type(url=url)
        self.assertIsInstance(machine_type, gcloudwrap.MachineType)
        self.assertEqual(machine_type.cpus, 8)
        self.assertEqual(machine_type.memory_in_mb, 1024)

    def test_ssh_keys_from_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key1 = "ecdsa-sha2-nistp256 " \
                   "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCcbTTrsI5OuXbfAnjraIX9u" \
                   "QMu0BNHgspD1VjS0OTubk9ng3jY7wZayTArhzSLXZicm7a9lcD/Coq6pHJBqiAQ= some-user@some-computer"

            key2 = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKQ6v13ixxwJKr+6mYDh" \
                   "tVjJhJiYIvBYCLmqLDlx/PlOUeF02TdP4kjYPISt+La8H+wjYMVkrEJUn4kRnCtPrmc= other-user@other-computer"

            path = pathlib.Path(tmpdir) / "public_keys.txt"

            with path.open('wt') as fid:
                # user specified in the file
                fid.write("devop:" + key1 + "\n")

                # no user specified in the file
                fid.write(key2 + "\n")

            keys = gcloudwrap.ssh_keys_from_file(path=path, default_user='some-default-user')

            self.assertEqual(2, len(keys))

            self.assertEqual(key1, keys[0].public_key)
            self.assertEqual('devop', keys[0].user)

            self.assertEqual(keys[1].public_key, key2)
            self.assertEqual(keys[1].user, 'some-default-user')


if __name__ == '__main__':
    unittest.main()
