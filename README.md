# TrinityTools
A collection of cloud security and operations tools from our Trinity project.

I've posted this project earlier than planned so I could release it with a conference presentation. Here is a brief description of the content and status and I will update this file as it progresses.

There are currently two tools in the collection. Both are being refactored from something I hacked together into full, properly structured, command line tools using the Methadone framework in Ruby. The functional versions of both tools are in the root directory and the new, refactored versions are being built in their designated subdirectories. The root versions will be removed once the Rafa toured versions are functional:

* rolling_update.rb - performs a rolling update of an auto scale group in AWS using defined parameters. It is designed to be used within Jenkins or another CI tool to swap out running instances to use a different AMI. For example, to push a patched version of an AMI into production instances on a rolling basis to reduce or eliminate downtime,
* is.rb - An automated incident response tool for AWS. The file ir-functional.rb is the one that currently works, with ir.rb currently broken for refactoring. The updates to this one will be far more intense and I have a long feature list I will start detailing in "issues". To run, you also need to take config.json.sample, complete it, and name it Config.json. This version relies on an IAM role for permissions to run, so if you aren't running this in an instance with a role attached you will need to swap out and use the alternate, Config-file based authentication (commented out in the code).

Rolling_update will be an easy conversion to a self contained command line tool. I have a lot more I want to update in incident response, especially automating much of the configuration information so it will create needed structures instead of failing if things aren't set properly in your account (such as the quarantine security group).

More to follow and any feature suggestions or other contributions appreciated.