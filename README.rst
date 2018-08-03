gcloudwrap
==========

``gcloudwrap`` provides a wrapper around the Google API client to help you manage your Google cloud (*i.e.* its
'compute' component). The original client provides all the needed functionality and ``gcloudwrap`` adds little in terms
of extras. However, we found it easier to have a thin wrapper around the cloud management to give us a domain language
closer to the tasks we had to repeatedly execute.

We initially found it hard to develop using original Google API client since it lacked type annotations and its dynamic
approach to object creation allowed no code inspection in an IDE such as PyCharm. Since
scripts involving cloud management usually take longer to execute, we found our development iterations to be fairly
long and often broke due to minor errors related to incorrect types. Therefore, we added type annotations so that the
static analyzer (such as mypy) would panic and catch the type errors early. This substantially facilitated the
development of the deployment scripts.

Mind that we have not wrapped all of Google Compute API. We focused only on the parts necessary for the deployment.
Please create an issue if you would like more functionality to be wrapped.

Scenarios
=========

Batch Jobs
----------
Writing a deployment script for large batch jobs is straight-forward with ``gcloudwrap``:

* You spin up a couple of machines.
* Use ``google-cloud-storage`` module to copy the necessary data from the storage.
* Use an SSH Python module (such as spurplus_) to install the dependencies, copy the released executables and initiate
  the processes within ``tmux`` (so that they stay alive after you exit the shell).

With this setup, no extra virtualization layer (such as Docker) is necessary, and you do not need to understand how to
set up and maintain an extra cluster management tool. It worked very well for us for different scales
(from trivial one-off batch jobs to large-scale deployments). Additionally, we found it much simpler to debug (and
resume afterwards) directly on a machine than going through an extra virtualization layer.

Deployment
----------
Apart from batch jobs, we intensively use ``gcloudwrap`` for the deployment in the cloud. Our workflow includes:

* Reserving an external address,
* Creating the instance,
* Tagging the instance (usually in order to modify the firewall rules),
* Authorizing the SSH keys,
* Creating and attaching persistent disks,
* Formatting the disks (if necessary) and mounting them and
* Running an initialization & installation script (based on an SSH module like spurplus_).

``gcloudwrap`` is intended to substantially simplify the process compared to the original Google Python API client.

(In case you need to deploy on other premises, we would suggest you to explicitly separate the
initialization script from the deployment script. The initialization scripts should accept user name and host name as
arguments and execute the commands remotely *via* SSH.

When you deploy on Google Cloud, create the instance and authorize your SSH key with it. Once the instance is up,
run the initialization script against its external IP address as host name and whatever user you authorized your
SSH key with.

If you need to deploy on other premises, ask them to authorize you your SSH key. Now you can simply run the same
initialization script with a different pair of user and host name.)

.. _spurplus: https://pypi.org/project/spurplus/

Related Projects
================

* https://github.com/google/google-api-python-client/ -- original Google API client whih we wrapped
* https://googlecloudplatform.github.io/google-cloud-python/ -- client for Google Cloud Platform services; it still
  lacked Compute support at the time we started developing ``gcloudwrap`` (2018-05-01)
* https://pypi.org/project/gwrappy/ -- user-friendly wrapper for Google APIs. This wrapper covers way more services
  that we had in mind. Since it does not focus on the deployment, it did not match with our idea to have a simple
  deployment language.
* https://libcloud.readthedocs.io/en/latest/index.html -- abstracts differences between cloud providers and provides
  a unified API. If you plan to use different cloud providers, this is a better alternative. In case you only want to
  use Google cloud, we found that such an abstraction library introduces unnecessary complexity.


Usage
=====

We tried to follow the naming of the API as much as possible. The definition and description of the API can be found
here: `Google Compute API`_. However, we complied to Python naming convention, and renamed all camelCase arguments into snake_case.

.. _`Google Compute API`: https://developers.google.com/resources/api-libraries/documentation/compute/v1/python/latest/

The following code snippet shows a common deployment which creates an instance with a persistent disk and a
reserved external IP address. The instance is tagged with 'default-allow-http' to open a HTTP port in its firewall.
Finally, we authorize a public SSH key with the instance.

.. code-block:: python

    import pathlib

    import gcloudwrap

    instance = 'some-instance'
    address = 'some-address'
    disk = 'some-persistent-disk'
    device_name = 'persistency'

    service_account = 'some-service-account@some-project-221984.iam.gserviceaccount.com

    public_ssh_key = pathlib.Path(
        '/some/path/to/ssh/id_rsa.pub').read_text()

    gce.addresses.insert(name=address)
    static_ip = gce.addresses.static_ip(
        address=address)

    gce.disks.insert(
        name=disk,
        disk_type='pd-standard',
        size_gb=5)

    gce.instances.insert(
        name=instance,
        machine_type='f1-micro',
        address=static_ip,
        service_account=service_account)

    gce.instances.attach_disk(
        instance=instance,
        disk=disk,
        device_name=device_name)

    # open up HTTP port
    tags = gce.instances.tags(instance=instance)
    tags.items.add('default-allow-http')
    gce.instances.set_tags(
        instance=instance, tags=tags)

    # authorize the SSH key
    keys = gcloudwrap.SSHKey(
        user='some-user',
        public_key=public_key)

    metadata = gce.instances.metadata(instance=instance)
    metadata.set_ssh_keys(keys=[key])

    gce.instances.set_metadata(
        instance=instance,
        metadata=metadata)

    # format the persistent disk and mount it
    ssh = gce.instances.ssh(
        instance=instance,
        user="some-devop-user")

    operator = gcloudwrap.Operator(call_fn=ssh.call)

    operator.format_disk(
        device_name=device_name)

    operator.mount_disk(
        device_name=device_name,
        path=pathlib.Path('/mnt/disks/persistency'))

Sometimes it is convenient to store the list of authorized SSH keys in a file and re-use this list when
deploying the instance. We provide a shortcut function ``gcloudwrap.ssh_keys_from_file`` to achieve that:

.. code-block:: python

    import gcloudwrap

    instance = 'some-instance'
    keys_path = '/path/to/some/keys.txt'

    keys = gcloudwrap.ssh_keys_from_file(
        path=keys_path,
        default_user='some-default-user')

    metadata = gce.instances.metadata(instance=instance)
    metadata.set_ssh_keys(keys=keys)

    gce.instances.set_metadata(
        instance=instance,
        metadata=metadata)


Installation
============

* Create a virtual environment:

.. code-block:: bash

    python3 -m venv venv3

* Activate it:

.. code-block:: bash

    source venv3/bin/activate

* Install ``gcloudwrap`` with pip:

.. code-block:: bash

    pip3 install gcloudwrap

* Set up the application-default credentials

.. code-block:: bash

    gcloud auth application-default login

Development
===========

* Check out the repository.

* In the repository root, create the virtual environment:

.. code-block:: bash

    python3 -m venv venv3

* Activate the virtual environment:

.. code-block:: bash

    source venv3/bin/activate

* Install the development dependencies:

.. code-block:: bash

    pip3 install -e .[dev]

* We provide a set of live tests. You need to set up your environment such that the credentials can be directly
  inferred by the tests. Apart from the credentials, you can also use the following environment variables:

    * ``TEST_GCLOUDWRAP_SERVICE_ACCOUNT`` to specify the service account attached to the instances created during the
      test. If unspecified, default service account of the GCE project is used.
    * ``TEST_GCLOUDWRAP_PREFIX`` to specify the prefix of all the created Google cloud resources; if not specified,
      equals "test-gcloudwrap"
    * ``TEST_GCLOUDWRAP_SSH_PUBLIC_KEY_PATH`` to specify the path to the SSH public key; if not specified,
      equals ~/.ssh/id_rsa.pub (where "~" is expanded to the user home directory)

  Mind that the live tests will use Google Cloud resources for which you will be billed. Always check that no resources
  are used after the tests finished so that you don't incur an unnecessary cost!

* We use tox for testing and packaging the distribution. Assuming that the virtual environment has been activated and
  the development dependencies have been installed, run:

.. code-block:: bash

    tox

* We also provide a set of pre-commit checks that lint and check code for formatting. Run them locally from an activated
  virtual environment with development dependencies:

.. code-block:: bash

    ./precommit.py

* The pre-commit script can also automatically format the code:

.. code-block:: bash

    ./precommit.py  --overwrite

Versioning
==========
We follow `Semantic Versioning <http://semver.org/spec/v1.0.0.html>`_. The version X.Y.Z indicates:

* X is the major version (backward-incompatible),
* Y is the minor version (backward-compatible), and
* Z is the patch version (backward-compatible bug fix).