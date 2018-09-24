#!/usr/bin/env python3

# pylint: disable=missing-docstring
# pylint: disable=logging-format-interpolation

import logging
import os
import pathlib
import re
import unittest
import uuid
import warnings
from typing import Callable, Any, Optional  # pylint: disable=unused-import

import gcloudwrap

# test environment variables
TEST_GCLOUDWRAP_SERVICE_ACCOUNT = os.environ.get('TEST_GCLOUDWRAP_SERVICE_ACCOUNT', None)
TEST_GCLOUDWRAP_PREFIX = os.environ.get('TEST_GCLOUDWRAP_PREFIX', 'test-gcloudwrap')
TEST_GCLOUDWRAP_SSH_PUBLIC_KEY_PATH = pathlib.Path(
    os.environ.get('TEST_GCLOUDWRAP_SSH_PUBLIC_KEY_PATH', os.path.expanduser("~/.ssh/id_rsa.pub")))


def ignore_resource_warnings(test_func: Callable[[Any], None]):
    """
    wraps the 'test_func' so that the resource warnings are ignored. In particualr, we need to ignore the unclosed
    ssl.SSLSocket resource warning;  see https://github.com/boto/boto3/issues/454 and
    https://stackoverflow.com/questions/26563711/disabling-python-3-2-resourcewarning

    :param test_func: to be wrapped
    :return:
    """

    def do_test(self, *args, **kwargs):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)
            test_func(self, *args, **kwargs)

    return do_test


LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=logging.ERROR)
logging.getLogger(__name__).setLevel(logging.INFO)


class TestInstances(unittest.TestCase):
    @ignore_resource_warnings
    def test_exists_create_and_delete(self):
        gce = gcloudwrap.Gce()
        instance = "{}-{}".format(TEST_GCLOUDWRAP_PREFIX, uuid.uuid4())

        self.assertFalse(gce.instances.exists(name=instance))

        try:
            LOGGER.info("Creating the instance {} ...".format(instance))
            gce.instances.insert(
                name=instance, machine_type='f1-micro', service_account=TEST_GCLOUDWRAP_SERVICE_ACCOUNT)
            self.assertTrue(gce.instances.exists(name=instance))
        finally:
            if gce.instances.exists(name=instance):
                LOGGER.info("Deleting the instance {} ...".format(instance))
                gce.instances.delete(instance=instance)

        self.assertFalse(gce.instances.exists(name=instance))

    @ignore_resource_warnings
    def test_exists_create_with_scopes_and_delete(self):  # pylint: disable=invalid-name
        gce = gcloudwrap.Gce()
        instance = "{}-{}".format(TEST_GCLOUDWRAP_PREFIX, uuid.uuid4())

        self.assertFalse(gce.instances.exists(name=instance))

        try:
            service_account = gcloudwrap.ServiceAccount(
                email=TEST_GCLOUDWRAP_SERVICE_ACCOUNT, scopes=['https://www.googleapis.com/auth/devstorage.read_only'])

            LOGGER.info("Creating the instance {} with service account {} ...".format(
                instance, service_account.__dict__))

            gce.instances.insert(name=instance, machine_type='f1-micro', service_account=service_account)

            self.assertTrue(gce.instances.exists(name=instance))
        finally:
            if gce.instances.exists(name=instance):
                LOGGER.info("Deleting the instance {} ...".format(instance))
                gce.instances.delete(instance=instance)

        self.assertFalse(gce.instances.exists(name=instance))

    @ignore_resource_warnings
    def test_ssh(self):
        gce = gcloudwrap.Gce()
        instance = "{}-{}".format(TEST_GCLOUDWRAP_PREFIX, uuid.uuid4())

        self.assertFalse(gce.instances.exists(name=instance))

        try:
            LOGGER.info("Creating the instance {} ...".format(instance))
            gce.instances.insert(
                name=instance, machine_type='f1-micro', service_account=TEST_GCLOUDWRAP_SERVICE_ACCOUNT)

            ssh = gce.instances.ssh(instance=instance, user="some-user")

            # Command succeeds
            retcode = ssh.call(command=["echo", "oi"])
            self.assertEqual(0, retcode)

            # Command fails
            retcode = ssh.call(command=["cat", "/tmp/doesnt-exist-{}".format(uuid.uuid4())])
            self.assertNotEqual(0, retcode)

            # Command succeeds
            ssh.check_call(command=["echo", "oi"])

            # Command fails and raises a RuntimeError
            runtime_error = None  # type: Optional[RuntimeError]
            try:
                ssh.check_call(command=["cat", "/tmp/doesnt-exist-{}".format(uuid.uuid4())])
            except RuntimeError as err:
                runtime_error = err

            self.assertIsNotNone(runtime_error)
            self.assertTrue(str(runtime_error).startswith("Failed to execute the command (return code 1): "))

        finally:
            if gce.instances.exists(name=instance):
                LOGGER.info("Deleting the instance {} ...".format(instance))
                gce.instances.delete(instance=instance)

        self.assertFalse(gce.instances.exists(name=instance))

    @ignore_resource_warnings
    def test_authorize_ssh_keys(self):
        gce = gcloudwrap.Gce()
        instance = "{}-{}".format(TEST_GCLOUDWRAP_PREFIX, uuid.uuid4())

        try:
            LOGGER.info("Creating the instance {} ...".format(instance))
            gce.instances.insert(
                name=instance, machine_type='f1-micro', service_account=TEST_GCLOUDWRAP_SERVICE_ACCOUNT)

            metadata = gce.instances.metadata(instance=instance)
            self.assertListEqual(metadata.ssh_keys(), [])

            public_key = TEST_GCLOUDWRAP_SSH_PUBLIC_KEY_PATH.read_text().strip()
            metadata.set_ssh_keys(keys=[gcloudwrap.SSHKey(user='tester', public_key=public_key)])

            gce.instances.set_metadata(instance=instance, metadata=metadata)

            metadata = gce.instances.metadata(instance=instance)
            ssh_keys = metadata.ssh_keys()
            self.assertEqual(len(ssh_keys), 1)
            ssh_key = ssh_keys[0]
            self.assertEqual(ssh_key.user, 'tester')
            self.assertEqual(ssh_key.public_key, public_key)

            # unauthorize everybody
            metadata.set_ssh_keys(keys=[])
            gce.instances.set_metadata(instance=instance, metadata=metadata)

            metadata = gce.instances.metadata(instance=instance)
            ssh_keys = metadata.ssh_keys()
            self.assertListEqual(ssh_keys, [])

        finally:
            if gce.instances.exists(name=instance):
                LOGGER.info("Deleting the instance {} ...".format(instance))
                gce.instances.delete(instance=instance)

    @ignore_resource_warnings
    def test_tags(self):
        gce = gcloudwrap.Gce()
        suffix = str(uuid.uuid4())
        instance = "{}-{}".format(TEST_GCLOUDWRAP_PREFIX, suffix)

        try:
            LOGGER.info("Creating the instance {} ...".format(instance))
            gce.instances.insert(
                name=instance, machine_type='f1-micro', service_account=TEST_GCLOUDWRAP_SERVICE_ACCOUNT)

            tags = gce.instances.tags(instance=instance)
            self.assertSetEqual(tags.items, set())

            tags.items.add('some-tag')
            gce.instances.set_tags(instance=instance, tags=tags)

            tags = gce.instances.tags(instance=instance)
            self.assertSetEqual(tags.items, {'some-tag'})

        finally:
            if gce.instances.exists(name=instance):
                LOGGER.info("Deleting the instance {} ...".format(instance))
                gce.instances.delete(instance=instance)

    @ignore_resource_warnings
    def test_custom_machine_type(self):
        gce = gcloudwrap.Gce()
        suffix = str(uuid.uuid4())
        instance = "{}-{}".format(TEST_GCLOUDWRAP_PREFIX, suffix)

        try:
            LOGGER.info("Creating the instance {} ...".format(instance))
            gce.instances.insert(
                name=instance,
                machine_type=gcloudwrap.new_machine_type(cpus=1, memory_in_mb=1024),
                service_account=TEST_GCLOUDWRAP_SERVICE_ACCOUNT)

            machine_type = gce.instances.machine_type(instance=instance)
            self.assertIsInstance(machine_type, gcloudwrap.MachineType)
            self.assertEqual(machine_type.cpus, 1)
            self.assertEqual(machine_type.memory_in_mb, 1024)

        finally:
            if gce.instances.exists(name=instance):
                LOGGER.info("Deleting the instance {} ...".format(instance))
                gce.instances.delete(instance=instance)


class TestDisks(unittest.TestCase):
    @ignore_resource_warnings
    def test_exists_create_and_delete(self):
        gce = gcloudwrap.Gce()

        name = "{}-persi-{}".format(TEST_GCLOUDWRAP_PREFIX, uuid.uuid4())

        self.assertFalse(gce.disks.exists(name=name))

        try:
            LOGGER.info("Creating the disk {} ...".format(name))
            gce.disks.insert(name=name, disk_type='pd-standard', description="some testing disk", size_gb=5)

            self.assertTrue(gce.disks.exists(name=name))
            self.assertFalse(gce.disks.attached(disk=name))

            disk = gce.disks.get(disk=name)
            self.assertEqual(disk.description, "some testing disk")
            self.assertEqual(disk.size_gb, 5)
            self.assertEqual(disk.name, name)
            self.assertEqual(disk.type, "pd-standard")
            self.assertEqual(disk.status, "READY")

            LOGGER.info("Resizing the disk {} ...".format(name))
            gce.disks.resize(disk=name, size_gb=6)

            disk = gce.disks.get(disk=name)
            self.assertEqual(disk.size_gb, 6)
        finally:
            if gce.disks.exists(name=name):
                LOGGER.info("Deleting the disk {} ...".format(name))
                gce.disks.delete(disk=name)


class TestAddresses(unittest.TestCase):
    @ignore_resource_warnings
    def test_exists_create_and_delete(self):
        gce = gcloudwrap.Gce()

        name = "{}-{}".format(TEST_GCLOUDWRAP_PREFIX, uuid.uuid4())

        self.assertFalse(gce.addresses.exists(name=name))

        try:
            LOGGER.info("Creating the address {} ...".format(name))
            gce.addresses.insert(name=name, description="some testing address")

            self.assertTrue(gce.addresses.exists(name=name))

            address = gce.addresses.get(address=name)
            self.assertEqual(address.status, gcloudwrap.AddressStatus.RESERVED)
            self.assertEqual(address.description, "some testing address")
            self.assertListEqual(address.users, [])

            self.assertTrue(
                re.match(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
                         address.address))

            self.assertNotEqual(address.id, '')
            self.assertNotEqual(address.self_link, '')
            self.assertEqual(address.name, name)

            self.assertEqual(gce.addresses.status(address=name), gcloudwrap.AddressStatus.RESERVED)
            self.assertFalse(gce.addresses.is_in_use(address=name))
            self.assertEqual(gce.addresses.static_ip(address=name), address.address)

        finally:
            if gce.addresses.exists(name=name):
                LOGGER.info("Deleting the address {} ...".format(name))
                gce.addresses.delete(address=name)


class TestIntegration(unittest.TestCase):
    @ignore_resource_warnings
    def test_that_it_works(self):
        # pylint: disable=too-many-locals
        gce = gcloudwrap.Gce()

        # suffix = uuid.uuid4()
        suffix = 'deleteme'
        address = "{}-{}".format(TEST_GCLOUDWRAP_PREFIX, suffix)

        disk = "{}-{}-persi".format(TEST_GCLOUDWRAP_PREFIX, suffix)
        device_name = 'persistency'

        instance = "{}-{}".format(TEST_GCLOUDWRAP_PREFIX, suffix)

        try:
            LOGGER.info("Creating the address {} ...".format(address))
            gce.addresses.insert(name=address, description="some testing address")
            static_ip = gce.addresses.static_ip(address=address)

            LOGGER.info("Creating the disk {} ...".format(disk))
            gce.disks.insert(name=disk, disk_type='pd-standard', description="some testing disk", size_gb=5)

            LOGGER.info("Creating the instance {} ...".format(instance))
            gce.instances.insert(
                name=instance,
                machine_type='f1-micro',
                address=static_ip,
                service_account=TEST_GCLOUDWRAP_SERVICE_ACCOUNT)

            self.assertEqual(gce.instances.external_ip(instance=instance), static_ip)
            self.assertTrue(gce.addresses.is_in_use(address=address))

            gce.instances.attach_disk(instance=instance, disk=disk, device_name=device_name)
            self.assertTrue(gce.disks.attached(disk=disk))

            disk_users = gce.disks.users(disk=disk)
            self.assertEqual(len(disk_users), 1)
            disk_user = disk_users[0]
            self.assertEqual(disk_user.instance, instance)

            address_details = gce.addresses.get(address=address)
            self.assertEqual(len(address_details.users), 1)
            address_user = address_details.users[0]
            self.assertEqual(address_user.instance, instance)

            metadata = gce.instances.metadata(instance=instance)
            public_key = TEST_GCLOUDWRAP_SSH_PUBLIC_KEY_PATH.read_text().strip()
            metadata.set_ssh_keys(keys=[gcloudwrap.SSHKey(user='tester', public_key=public_key)])
            gce.instances.set_metadata(instance=instance, metadata=metadata)

            tags = gce.instances.tags(instance=instance)
            tags.items.add('default-allow-http')
            gce.instances.set_tags(instance=instance, tags=tags)

            ssh = gce.instances.ssh(instance=instance, user="tester")
            operator = gcloudwrap.Operator(call_fn=ssh.call)
            operator.format_disk(device_name=device_name)

            operator.mount_disk(device_name=device_name, path=pathlib.Path('/mnt/disks/persistency'))

            retcode = ssh.call(command=['bash', '-c', 'echo hello > /mnt/disks/persistency/hello.txt'])
            assert retcode == 0

        finally:
            if gce.instances.exists(name=instance):
                LOGGER.info("Deleting the instance {} ...".format(instance))
                gce.instances.delete(instance=instance)

            if gce.disks.exists(name=disk):
                LOGGER.info("Deleting the disk {} ...".format(disk))
                gce.disks.delete(disk=disk)

            if gce.addresses.exists(name=address):
                LOGGER.info("Deleting the address {} ...".format(address))
                gce.addresses.delete(address=address)


if __name__ == '__main__':
    unittest.main()
