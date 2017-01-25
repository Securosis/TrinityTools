# Securitysquirrel Incident Response workflow proof of concept by rmogull@securosis.com
# Copyright 2014 Rich Mogull and DisruptOps, Inc. No other use is authorized.

# You must install the listed gems..
# This version is a subset of the public SecuritySquirrel code, enhancing the Incident Response workflow

# TODO list:
# TODO Adjust the omnisearch to search across regions and accounts. Basically, iterate through all accounts configured for that user.
#   This will eventially pull based on accounts configured for the given project.
# TODO When we convert this to a real UI, we will want to allow filtering in the search box, per UX guidelines.
# TODO Take a list of regions, and re-code the omnisearch to roll through all configured regions
# TODO Add search for Trinity projects and tags. For projects, we can add "search other projects"
#   as an option, in case they opened the workflow in the wrong project.
# TODO Add pagination for all searches. Again, for speed, not doing that now.
# TODO Adjust tag pre-fetch and search to handle multiple accounts and regions.
# TODO Once the user searches on an instance, build instance metadata and analysis so user can research
#   instance before taking action. 
# TODO Adjust the IP search to account for multiple instances due to overlapping VPCs and accounts, and let the user select.
# TODO evaluate if IAM policy to restrict IR access is set up properly and fix if it isn't
# TODO evaluate if Quarantine security group is configured properly, and fix if it isn't
# TODO update all use of credentials to use AssumeRole, and ideally a policy template
# TODO change the tagging from "IR" to pull the designated tag for the workflow from the DB
# TODO determine if variable scopes are set properly
# TODO remove all the text/status that currently sends to the console for debugging
# TODO add state management
# TODO add logging
# TODO check that code will work with EC2-classic. This was all tested on EC2-VPC
# TODO fix to check security group for current VPC, not account/region.

# How to create your configuration file:
#
# For the most part it is easy, but until I add some error checking the config needs to be perfect
# 1. Everything needs to be in the same VPC. If you haven't set up a new VPC, it will work in yoru default.
# 2. Create a quarantine security group without any ingress rules.
# 3. Create an analysis security group. The rules don't matter for the demo
# 4. Use those group IDs in the configuration file/DB entry
# For this to work in demo mode, everything has to be on one account, in one region, in one VPC. It won't be hard to update the code to be more flexible, but that's the current limitation.




require "rubygems"
require "aws-sdk"
require 'aws-sdk-core'
require "json"
require 'open-uri'
require 'netaddr'
require 'pry'

# class for performing an omnisearch

class OmniSearch
  def initialize(search_item)
    @search_item = search_item
    # Load configuration and credentials from a JSON file. Right now hardcoded to config.json in the app drectory.
    # Load from config file in same directory as code
    # In the future, we will need to adjust this to rotate through all accounts and regions for the user. AssumeRole should help.
    creds = JSON.load(File.read('config.json'))
    # Set credentials... using hard coded for this PoC, but really should be an assumerole in the future.
    # creds = Aws::Credentials.new("#{creds["aws"]["AccessKey"]}", "#{creds["aws"]["SecretKey"]}")
    # Create clients for the various services we need. Loading them all here and setting them as Class variables.
    @@ec2 = Aws::EC2::Client.new(region: "#{$region}")
    @@loadbalance = elasticloadbalancing = Aws::ElasticLoadBalancing::Client.new(region: "#{$region}")
  end
  
  def identify_instance
    # determine if we are being given an instance ID, IP address, or tag
    # need to change this over time to pre-fetch as needed for performance.
    # should probably pre-fetch when the workload launches, and store the results in elasticache
    # 
    
    # check to see if the search term is an instance ID. If so, we're done.
    if @search_item[0..1] == "i-" 
     return @search_item
     # check to see if it is an IP address
    elsif  (/(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/x.match(@search_item))
      # Check to see if the IP is not Internet routable
      if ( /(^127\.0\.0\.1)|\n(^10\.)|\n(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|\n(^192\.168\.)\n/x.match(@search_item))
        #Find the instance ID based on the internal IP address
        search_result = @@ec2.describe_instances(
          filters: [
            {
              name: "private-ip-address",
              values: ["#{@search_item}"],
            },
          ]
        )
        if search_result.reservations.first.members.include?(:instances)
          search_result = search_result.reservations.first.instances.first.instance_id
          return search_result
        else
          search_result = "This is an non-Internet-routable IP address, but is not associated with an instance in your account and region #{$region}."
          return search_result
        end
        
      else
        # See if the instance ID is an elastic IP or external IP address and return the associated instance
        # Right now, we also see if it is an AWS IP but in a different region, or not tied to the current account
        # We will update that later to cross-region and cross-account search.
        begin
          # Pull the elastic IP based on the IP. If it doesn't exist, set a not-found value
          # We will overwrite that later if we find the instance a different way
          # We start with EIP since that is much faster to search on
          search_result = @@ec2.describe_addresses(public_ips: ["#{@search_item}"])
          if search_result.addresses.first.instance_id != nil
            search_result = search_result.addresses.first.instance_id
            return search_result
          else search_result = "This is an elastic IP in your account without an associated instance."
            return search_result
          end
        rescue Aws::EC2::Errors::ServiceError
          # since we didn't find an EIP, see if we can find it as one of AWS's public IPs.
          # we use the pre-cached list of all AWS IP ranges
          
          # convert IP to CIDR using the netaddr gem
          ip = NetAddr::CIDR.create("#{@search_item}/32")
          # loop through the current list of AWS CIDR ranges to see if the IP is inside AWS
          $cidr_list.each do |cidr|
            # pull the current CIDR range and convert to a CIDR object
            curcidr = cidr["ip_prefix"]
            curcidr = NetAddr::CIDR.create("#{curcidr}")
            # See if the submitted IP is within that range
            if ip.is_contained?(curcidr)
              # now we know it is an IP associated with AWS. Check to see if it is associated with an instance.
              # THIS VERSION ONLY WORKS IF THE REGIONS MATCH!!!
              # Later we will check multiple regions, but right now it only checks in the configured region and throws
              #  an error result if the IP is from another region.
              
              # check to see if regions match
              if $region == "#{cidr["region"]}"
                # check for any instance with that IP address in the region
                  search_result = @@ec2.describe_instances(
                    filters: [
                      {
                        name: "ip-address",
                        values: ["#{@search_item}"],
                      },
                    ]
                  )
                  # TODO check to see if this conditional works
                  if search_result.reservations.first.members.include?(:instances)
                    search_result = search_result.reservations.first.instances.first.instance_id
                    return search_result
                  else
                    search_result = "This is an AWS IP address in the current region, but not associated with the current account."
                    return search_result
                  end
              else
                search_result = "This is an AWS IP address in #{cidr["region"]}, not the current region of #{$region}"
                return search_result
              end
              
              return search_result
            end
          end
          
          search_result = "We are unable to identify an instance with that IP address"
        end
        return search_result
      end
    #identify based on DNS, which could be AWS DNS or ELB. For now, we are skipping Route 53 and regular (registered) DNS
   # elsif 
    #identify any instances associated with the tag (if any) and then have the user select
    elsif $tag_string.include?("#{@search_item}")
      # We start just looking for arbitrary string match. 
      # In the future, the next step is to determine the account and region
      # Then to search that region and build a list of instances with the key and value
      
      # build list of instances with the tag as the key
      search_result_by_key = @@ec2.describe_instances(
        filters: [
          {
            name: "tag-key",
            values: ["#{@search_item}"],
          },
        ]
      )
      
      # build list of instances with the tag as the value
      search_result_by_value = @@ec2.describe_instances(
        filters: [
          {
            name: "tag-value",
            values: ["#{@search_item}"],
          },
        ]
      )
      
      #conditionals to build out options list, need to loop through and build select box next
      
      if search_result_by_key.reservations.first != nil
        puts search_result_by_key.to_h
      end
      
      if search_result_by_value.reservations.first != nil
          puts search_result_by_value.to_h
      end
      
      
      # For both, include the instance ID, the key, and the value
      # Have user select the instance
      
      
      
  # elsif ***when we have project names and tags, this is where we will add that search function***
    else
      puts "We cannot identify any instances with the listed traits"
    end
    
  end
  
end

# class for incident response functions like quarantine.
class IncidentResponse
  def initialize(instance_id)
    @instance_id = instance_id
    
    # Load configuration and credentials from a JSON file. Right now hardcoded to config.json in the app drectory.
    # TODO update to pull credentials from Trinity DB
    # TODO update to be able to handle multiple accounts and regions
    
    # Load from config file in same directory as code
    # In the future, we will need to adjust this to rotate through all accounts and regions for the user. AssumeRole should help.
    config = JSON.load(File.read('config.json'))
    #  credentials... using hard coded for this PoC, but really should be an assumerole in the future.
#    creds = Aws::Credentials.new("#{config["aws"]["AccessKey"]}", "#{config["aws"]["SecretKey"]}")
    # Create clients for the various services we need. Loading them all here and setting them as Class variables.
    @@ec2 = Aws::EC2::Client.new(region: "#{$region}")
    
    # Set application configuration variables. Im hunting for a more efficient way to dynamically pull the region,
    # but haven't found one that works yet. Thus, for now, sticking with elsif. Suggestions appreciated.
    
    # Remember that not all AWS services are available in all regions. Everything in this version of the tool should work.
    

    if $region == "us-west-1"
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["us-west-1"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["us-west-1"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["us-west-1"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["us-west-1"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["us-west-1"]["User"]}"
    elsif $region == "us-west-2"
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["us-west-2"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["us-west-2"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["us-west-2"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["us-west-2"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["us-west-2"]["User"]}"
    elsif $region == "us-east-1"
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["us-east-1"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["us-east-1"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["us-east-1"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["us-east-1"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["us-east-1"]["User"]}"
    elsif $region == "eu-west-1"
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["eu-west-1"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["eu-west-1"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["eu-west-1"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["eu-west-1"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["eu-west-1"]["User"]}"
    elsif $region == "ap-southeast-1"
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["ap-southeast-1"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["ap-southeast-1"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["ap-southeast-1"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["ap-southeast-1"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["ap-southeast-1"]["User"]}"
    elsif $region == "ap-southeast-2"
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["ap-southeast-2"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["ap-southeast-2"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["ap-southeast-2"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["ap-southeast-2"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["ap-southeast-2"]["User"]}"
    elsif $region == "ap-northeast-1"
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["ap-northeast-1"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["ap-northeast-1"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["ap-northeast-1"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["ap-northeast-1"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["ap-northeast-1"]["User"]}"
    elsif $region == "sa-east-1"
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["sa-east-1"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["sa-east-1"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["sa-east-1"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["sa-east-1"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["sa-east-1"]["User"]}"
    else
      #default to us-east-1 in case something fails
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["us-east-1"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["us-east-1"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["us-east-1"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["us-east-1"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["us-east-1"]["User"]}"
    end

   
  end
  
  def quarantine
    # this method moves the provided instance into the Quarantine security group defined in the config file.
    # TODO update to pull the configuration details from the Trinity database
    puts ""
    puts "Quarantining #{@instance_id}..."
    quarantine = @@ec2.modify_instance_attribute(instance_id: "#{@instance_id}", groups: ["#{@QuarantineGroup}"])
    puts "#{@instance_id} moved to the Quarantine security group from your configuration settings."
   end
  
  def tag
    # this method adds an "status => IR" tag to the instance.
    # If you properly configure your IAM policies, this will move ownership fo the instance to the security
    # team and isolate it so no one else can terminate/stop/modify/etc.
    puts "Tagging instance with 'IR'..."
    tag = @@ec2.create_tags(resources: ["#{@instance_id}"], tags: [
    {
      key: "SecurityStatus",
      value: "IR",
    },
  ],)
  puts "Instance tagged and IAM restrictions applied."
  end
  
  def snapshot
    # This method determines the volume IDs for the instance, then creates snapshots of those def volumes(args)
    # Get the instance details for the instance
    instance_details = @@ec2.describe_instances(
      instance_ids: ["#{@instance_id}"],
    )
    
    # find the attached block devices, then the ebs volumes, then the volume ID for each EBS volume. This involves walking the response tree.

    puts "Identifying attached volumes..."
    block_devices = instance_details.reservations.first.instances.first.block_device_mappings
    ebs = block_devices.map(&:ebs)
    volumes = ebs.map(&:volume_id)
    # start an empty array to later track and attach the snapshot to a forensics storage volume
    @snap = []
    volumes.each do |vol|
      puts "Volume #{vol} identified; creating snapshot"
      # Create a snapshot of each volume and add the volume and instance ID to the description.
      # We do this since you can't apply a name tag until the snapshot is created, and we don't want to slow down the process.
      timestamp = Time.new
      snap = @@ec2.create_snapshot(
        volume_id: "#{vol}",
        description: "IR volume #{vol} of instance #{@instance_id} at #{timestamp}",
      )
      puts "Snapshots complete with description: IR volume #{vol} of instance #{@instance_id}  at #{timestamp}"
      # get the snapshot id and add it to an array for this instance of the class so we can use it later for forensics
      @snap = @snap << snap.snapshot_id
    end
      # Launch a thread to tag the snapshots with "IR" to restrict to the security team.
      # We do this since we need to wait until the snapshot is created for the tags to work.
      
      snapthread = Thread.new do
        snap_array = Array.new
        @snap.each do |snap_id|
          snap_array << "#{snap_id}"
        end
      
        status = false
        until status == true do
          snap_details = @@ec2.describe_snapshots(snapshot_ids: snap_array)
          snap_details.each do |snapID|
            if snap_details.snapshots.first.state == "completed"
              status = true
            else
              status = false
            end
          end
        end

          @@ec2.create_tags(
            resources: snap_array,
            tags: [
              {
                key: "SecurityStatus",
                value: "IR",
              },
            ],
          )

      end
  end
  

  def forensics_analysis
    # This method launches an instance and then creates and attaches storage volumes of the IR snapshots. 
    # It also opens Security Group access between the forensics and target instance.
    # Right now it is in Main, but later I will update to run it as a thread, after I get the code working.
    
    # set starting variables 
    alpha = ("f".."z").to_a
    count = 0
    block_device_map = Array.new
    
    # Build the content for the block device mappings to add each snapshot as a volume. 
    # Device mappings start as sdf and continue up to sdz, which is way more than you will ever need.
    @snap.each do |snapshot_id|
      count += 1
      # pull details to get the volume size
      snap_details = @@ec2.describe_snapshots(snapshot_ids: ["#{snapshot_id}"])
      vol_size = snap_details.snapshots.first.volume_size
      # create the string for the device mapping
      device = "/dev/sd" + alpha[count].to_s
      # build the hash we will need later for the bock device mappings
      temphash = Hash.new
      temphash = {
      device_name: "#{device}",
      ebs: {
        snapshot_id: "#{snapshot_id}",
        volume_size: vol_size,
        volume_type: "standard",
        }
      }
      # add the hash to our array
      block_device_map << temphash
      
    end

    # Notify user that this will run in the background in case the snapshots are large and it takes a while
    
    puts "A forensics analysis server is being launched in the background in #{@region} with the name"
    puts "'Forensics' and the snapshots attached as volumes starting at /dev/sdf "
    puts "(which may show as /dev/xvdf). Use host key #{@ForensicsSSHKey} for user #{@ForensicsUser}"
    puts ""
    
    # Create array to get the snapshot status via API

    snaparray = Array.new
    @snap.each do |snap_id|
      snaparray << "#{snap_id}"
    end 
    
    # Launch the rest as a thread since waiting for the snapshot may otherwise slow the program down.
    
    thread = Thread.new do
          # Get status of snapshots and check to see if any of them are still pending. Loop until they are all ready.
        status = false
        until status == true do
          snap_details = @@ec2.describe_snapshots(snapshot_ids: snaparray)
          snap_details.each do |snapID|
            if snap_details.snapshots.first.state == "completed"
              status = true
            else
              status = false
            end
          end
        end
    
        forensic_instance = @@ec2.run_instances(
          image_id: "#{ @ForensicsAMI}",
          min_count: 1,
          max_count: 1,
          instance_type: "t1.micro",
          key_name: "#{@ForensicsSSHKey}",
          security_group_ids: ["#{@AnalysisSecurityGroup}"],
          placement: {
              availability_zone: "us-west-2a"
            },        
          block_device_mappings: block_device_map
        )
        # Tag the instance so you can find it later
        temp_id = forensic_instance.instances.first.instance_id
        
        tag = @@ec2.create_tags(
          resources: ["#{temp_id}"],
          tags: [
            {
              key: "IncidentResponseID",
              value: "Forensic Analysis Server for #{@instance_id}",
            },
            {
              key: "SecurityStatus",
              value: "IR",
            },
            {
              key: "Name",
              value: "Forensics",
            },
          ],
        )
        
        # create variable to store the IR server in the Trinity database
        # TODO store this variable in the database to track later for the incident
        ir_server_details = {:instance_id => "#{@instance_id}", :timestamp => timestamp, :incident_id => "placeholder"}
      end

  end
  
  def store_metadata
    # Method collects the instance metadata and stores as a JSON variable
    # TODO send data to Dynamo, with incident ID
    # TODO update the incident_id to reflect the workflow id 

    data = @@ec2.describe_instances(instance_ids: ["#{@instance_id}"])
    timestamp = Time.new
    incident_id = {:timestamp => timestamp, :incident_id => "placeholder"}
    # metadata = data.reservations.first.instances.to_h
    metadata = data.to_json
    puts "Instance metadata recorded"
  end
  
  def testing
    # testing some tag code
    instancelist = @@ec2.describe_tags(
    filters: [
    {
      name: "key",
      values: ["SecurityStatus"]
    }
    ]
    )
    puts instancelist.to_h
  end

  
end

# class for incident analysis

class IncidentAnalysis
  def initialize(instance_id)
    @instance_id = instance_id
    
    # Load configuration and credentials from a JSON file. Right now hardcoded to config.json in the app drectory.
    # TODO update to pull credentials from Trinity DB
    # TODO update to be able to handle multiple accounts and regions
    
    # Load from config file in same directory as code
    # In the future, we will need to adjust this to rotate through all accounts and regions for the user. AssumeRole should help.
    config = JSON.load(File.read('config.json'))
    #  credentials... using hard coded for this PoC, but really should be an assumerole in the future.
#    creds = Aws::Credentials.new("#{config["aws"]["AccessKey"]}", "#{config["aws"]["SecretKey"]}")
    # Create clients for the various services we need. Loading them all here and setting them as Class variables.
    @@ec2 = Aws::EC2::Client.new(region: "#{$region}")
    @@autoscaling = Aws::AutoScaling::Client.new(region: "#{$region}")
    @@loadbalance = elasticloadbalancing = Aws::ElasticLoadBalancing::Client.new(region: "#{$region}")
    # Load the analysis rules
    # TODO pull from database instead of file
    @@rules = JSON.load(File.read('analysis_rules.json'))
  end
  
  # method to determine if instance is in an autoscaling group
  def autoscale
    @metadata  = @@ec2.describe_instances(instance_ids: ["#{@instance_id}"])
    tags = @metadata.reservations.first.instances.first
    # covert to hash to make this easier
    tags = tags.to_h
    tags = tags[:tags]
    # quick check to avoid having to iterate through all the tags to see if the one we need is there.
    temp_tags = tags.to_s
    if temp_tags.include?("aws:autoscaling:groupName")
      tags.each do |curtag|
        if curtag[:key] == "aws:autoscaling:groupName"
          @autoscaling = curtag[:value]
        end
      end
    else
      @autoscaling = "false"
     end
  end
  
  def assess_application
    # This method determines what potential services/applications are running on the instance. 
    # Right now it only checks security groups... later we will plug it into Chef/etc.
    # For this version, we only check inbound since outbound is less indicative of app role.
    
    # Pull the security groups for our instance
    # TODO Note that I need to add a conditional here if this ever runs before the autoscaling check or it won't have instance metadata
    
    secgroups = @metadata.reservations.first.instances.first.security_groups
    # Get the group IDs
    secgroups = secgroups.map(&:group_id)
    # Now pull the details for all those groups
    secgroups = @@ec2.describe_security_groups(group_ids: secgroups)
    
    
    

    # Set initial empty variables to hold the data
    @portlist = {}
    @secgrouplist = []
    @internal_secgrouplist = []
    # interate through each security group
    secgroups.security_groups.each do |group|
      # pull the security group IDs so we can use them later to find connections
      @secgrouplist << group.group_id
      # now pull all the ports into a hash. Start by seeing if port is already on list, if not, add the key
        group.ip_permissions.each do |port|
          if @portlist.has_key?(port.from_port.to_s) == false
            @portlist[port.from_port.to_s] = []
          end
          # Now iterate through the ip ranges to get the ip list       
          port.ip_ranges.each do |cidr|
            if cidr.cidr_ip != nil
              tempport = @portlist[port.from_port.to_s]
              tempport << cidr.cidr_ip
              @portlist[port.from_port.to_s] = tempport
            end
          end
          
            # pull other security groups allowed to connect to this one
            port.user_id_group_pairs.each do |internalsg|
             if internalsg.group_id != nil
               tempport = @portlist[port.from_port.to_s]
               tempport << internalsg.group_id
               @portlist[port.from_port.to_s] = tempport
               # this may be redundent, keeping it for now in case we just want a short list of connected security groups
               @internal_secgrouplist << internalsg.group_id
              end
            end

        end
      end
      
      # This next section finds connected security groups and maps
      # the incoming ports. Again, to later help determine the app stack.
      
      # Pull all security groups that allow access from this group.
      secgroups = @@ec2.describe_security_groups( filters: [
    {
      name: "ip-permission.group-id",
      values: @secgrouplist
    }
  ])
      # set the initial hash to store the values.
    @connected_secgroups = {}
    # iterate through each group
    secgroups.security_groups.each do |group|
      # See if we already have this group in our hash. If not, create it.
    if @connected_secgroups.has_key?(group.group_id) == false
      @connected_secgroups[group.group_id] = []
    end
    # Iterate through all the security group rules
      group.ip_permissions.each do |port|
        # Skip to the permissions part of the rule that ties to other security groups, since we know that's our focus.
        port.user_id_group_pairs.each do |internalsg|
          # Since we are checking the receiving side, which has a ton of rules, we need to check if the rule 
          # we are inside of actually allows a connection from the security group the instance is in.
          # Without this, we would add all the rules for this group, not just the ones tied to our instance
          if @secgrouplist.include?(internalsg.group_id)
            templist = @connected_secgroups[group.group_id]
            templist << port.from_port.to_s
            @connected_secgroups[group.group_id] = templist
          end
        end
      end
    end
    
    # Determine which apps are Internet-facing. Don't rely just on security groups, just to be safe.
    # We could do this as part of the analysis later, but breaking it out here since we don't know the exact flow yet.
    
    @internal_external_ports = {}
    @portlist.each do |port, ips|
      if @internal_external_ports.has_key?(port) == false
        @internal_external_ports[port] = ""
      end
      ips.each do |ip|
        # Regex and comparison to see if IP is Internet routable, or a security group
        # This redundency is in case internal routing was used instead of security groups (a mistake we should create a workflow to find).
        
        # ***At this point we don't check ACLs, which we should probably add***
        
        if ( /(^127\.0\.0\.1)|\n(^10\.)|\n(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|\n(^192\.168\.)\n/x =~ ip[0..-4] ) or (ip.include? "sg")
          if @internal_external_ports[port] == ""
            @internal_external_ports[port] = "internal"
          elsif @internal_external_ports[port] == "external"
            @internal_external_ports[port] = "both"
          end
        else 
          @internal_external_ports[port] = "external"
        end
      end
    end
    
    # TODO Determine if the instance is behind an Elastic Load Balancer
    # Pull load balancers
    @elb = ""
    begin
      elbs = @@loadbalance.describe_load_balancers()
      # Cycle through ELBs to find any the instance is in
      elbs.each do |curelb|
        # create a quick string to see if the instance is in the load balancer without having to walk the response tree
        curelb = curelb.to_h
        if curelb.to_s.include?("#{@instance_id}")
          # if so, set the variable to send to the analysis method
          @elb = curelb
        end
       end
      rescue Aws::EC2::Errors::ServiceError
      end
 


  end
  
  # method to perform analysis of all the data collected, which will be returned as a single JSON object
  def analyze
    # TODO remove all the text output that is here for testing
    
    # Initialize the hash we will convert to JSON and return
    analyze_results = Hash.new
    analyze_results[:flat_secgroup] = "false"
    
    # Analyze autoscaling
    if @autoscaling != "false"      
      autoscale_details = @@autoscaling.describe_auto_scaling_groups(auto_scaling_group_names: [@autoscaling])
      launch_time = autoscale_details.auto_scaling_groups.first.created_time
      instances = autoscale_details.auto_scaling_groups.first.instances.map(&:instance_id)
      instances.delete(@instance_id)
      analyze_results[:autoscale] = {:group_name => "#{@autoscaling}", :launch_time => "#{launch_time}", :instances => instances}
      puts "This instance is in an autoscaling group. It is likely safe to terminate. The autoscaling group was launched at #{launch_time} and the following other instances are in the group and should be investigated: #{instances}"
     else
       puts "This instance is not in an autoscaling group. Stopping or terminating may break things."
       analyze_results[:autoscale] = "false"
     end
     
     # Determine if the instance is in a security group that allows internal/lateral connections (a "flat" security group)
     templist = []
     @secgrouplist.each do |group|
       if @internal_secgrouplist.include?(group)
        templist << group
       end
     end
     if templist != []
       analyze_results[:flat_secgroup] = templist
       puts "WARNING! This instance is in at least one security group that allows internal connections. This is similar to a flat network or subnet, and other instances in the same group may be at risk. Instances in the following Security Groups are at risk: "
       puts analyze_results[:flat_secgroup].to_s
     else
       puts "Other instances in the same security groups were not accessible from this instance."
     end
     
     # Determine which known services are open, internally and externally
     # TODO need to update this to account for ELBs!!!
     
     services = {}
     # build the rules so we can search more easily by port. This is to avoid iterating inside the logic later.
     # this inverts the hash, but adds the original key as the value for every element when value is an array
     rules = {}
     @@rules["ServicesByPort"].each do |key, value|
       value.each do |val|
         rules[val] = key
       end
     end
        
     # Now check to see which ports correlate with highlighted/known services
     @internal_external_ports.each do |port, location|
       service = rules[port]
       if service != nil
         services[service] = {:location => location, :port => port}
       end
     end
     
     # If the instance is behind an elb, determine if it is internal or external
     if @elb != ""
       elb_exposure = @elb[:load_balancer_descriptions].first[:scheme]
       elb_name = @elb[:load_balancer_descriptions].first[:load_balancer_name]
       elb_listeners = @elb[:load_balancer_descriptions].first[:listener_descriptions]
       puts "This instance is behind the elastic load balancer #{elb_name} which is #{elb_exposure}. In production, we will ask you to click here to see the details"
       analyze_results[:load_balancer] = {:elb_name => elb_name, :elb_exposure => elb_exposure, :elb_listeners => elb_listeners, :elb_full_details => @elb}    
     else
       analyze_results[:load_balancer] = "none"
     end
     
     # Add the result to our return value
     
     analyze_results[:services] = services
     
     # And also dump the entire port list for reference
     analyze_results[:full_port_list] = @portlist

     # temp code to display results here
     # TODO remove this
     
     puts "We have identified the following services, and which are exposed to the Internet:"
     services.each do |service, info|
       if info[:location] == "internal"
         location = "has Internal access only"
       elsif info[:location] == "external"
         location = "is Internet accessible"
       else
         location = "accessible from the Internet and internally"
       end
       puts "This instance is running a " + service + " that " + location + " on port " + info[:port]
     end

     # Pull instance owner information. We are limited to the SSH key since AWS can't provide the IAM user that launched the instance
     # TODO determine who launched the instance or ASG based on CloudTrail
     user_key = @metadata.reservations.first.instances.first.key_name
     analyze_results[:user_key] = user_key
     puts "This instance was launched with SSH key #{user_key}. This could indicate the owner."
     
     # Pull AMI, then find other instances using the same AMI
     ami = @metadata.reservations.first.instances.first.image_id
     same_ami = @@ec2.describe_instances(filters: [
      {
        name: "image-id",
        values: ["#{ami}"]
      }])
      
      same_ami_instances = []
      same_ami.reservations.each do |curres|
        same_ami_instances << curres.instances.map(&:instance_id)
      end
      analyze_results[:image] = {:image_id => "#{ami}", :instances_with_same_ami => same_ami_instances}
      
      # convert to JSON to send to the front end
      analyze_results = analyze_results.to_json
      
      puts "This instance was based on the image #{ami}. There are #{same_ami_instances.count} other instances based on that image that may have the same vulnerabilities."  
      puts ""
      puts ""
      puts "The full JSON of information to be sent to the front end is: "
      puts analyze_results
  end
  
end

def region
  # A method for setting the availability zone
  # Pull the configuration so we only show regions that are configured
  configfile = File.read('config.json')
  config = JSON.parse(configfile)
  
   puts "\e[H\e[2J"
   puts "Current region: #{$region}. Select a new region:"
   puts "(Only regions you have configured are shown)"
   puts ""
   puts ""

   if config["aws"]["RegionSettings"].has_key?('us-east-1')
        puts "1. us-east-1 (Virginia)"
      end
   if config["aws"]["RegionSettings"].has_key?('us-west-1')
        puts "2. us-west-1 (California)"
  end
    if config["aws"]["RegionSettings"].has_key?('us-west-2')
       puts "3. us-west-2 (Oregon)"
  end
    if config["aws"]["RegionSettings"].has_key?('eu-west-1')
        puts "4. eu-west-1 (Ireland)"
    end
    if config["aws"]["RegionSettings"].has_key?('ap-southeast-1')
        puts "5. ap-southeast-1 (Singapore)"
    end
    if config["aws"]["RegionSettings"].has_key?('ap-southeast-2')
       puts "6. ap-southeast-2 (Sydney)"
    end
    if config["aws"]["RegionSettings"].has_key?('ap-northeast-1')
        puts "7. ap-northeast-1 (Tokyo)"
    end
    if config["aws"]["RegionSettings"].has_key?('sa-east-1')
        puts "8. sa-east-1 (Sao Paulo)"
    end

  
  puts ""
  print "New region: "
  option = gets.chomp
  $region = case option
    when "1" then "us-east-1"
    when "2" then "us-west-1"
    when "3" then "us-west-2"
    when "4" then "eu-west-1"
    when "5" then "ap-southeast-1"
    when "6" then "ap-southeast-2"
    when "7" then "ap-northeast-1"
    when "8" then "sa-east-1"
    else puts "Error, select again:"
   end

end

def prefetch
  # Separate threads to pre-load values to speed up the omnisearch.
  # When we move to production, we may want to allow the user to refresh this somehow.
  # Perhaps when the search box loads, before they enter values. Or with a refresh button on the search bar.
  
  # Load the AWS IP ranges and convert to a hash as a background thread.
  cidr_thread = Thread.new do
    cidr_remote  = open('https://ip-ranges.amazonaws.com/ip-ranges.json') {|f| f.read }
    cidr_list = JSON.parse(cidr_remote)
    
    # start working again here!!!!!
    $cidr_list = cidr_list["prefixes"]
  end
  
  # Load all the tags and values. This speeds up the process of determining if we are using a tag search
  # Right now, this only works for the current region. 
  # In the future, we need to update it for all regions.
  #
  # Technically we can search these after getting the search term from the user, but this is likely faster
  # when we integrate into the UI. We *don't* do this for IP addresses since that will always be a 1 to 1 match
  # We can tune these later, once we play with it more.
  
 # tag_thread = Thread.new do
    creds = JSON.load(File.read('config.json'))
    # Set credentials... using hard coded for this PoC, but really should be an assumerole in the future.
    # creds = Aws::Credentials.new("#{creds["aws"]["AccessKey"]}", "#{creds["aws"]["SecretKey"]}")
    # Create client for EC2. May need to expand to other services later.
    # ec2 = Aws::EC2::Client.new(credentials: creds, region: "#{$region}")
    ec2 = Aws::EC2::Client.new(region: "#{$region}")
    # Pull tags.
    tag_list = ec2.describe_tags()   
    # Convert to a hash since, later, we will need to combine results from multiple sources.
    $tags = tag_list
   # tag_list = tag_list.to_h
    # Create a string of the tags. We do this to allow searching on even a partial tag key or value
    # **In the future, this should be a hash with the account, region, and tag string as values so we
    #   can narrow our search to the right part **
    $tag_string = tag_list.to_s
#  end
end

# Body code
# Load defaults. Rightnow, just the region.
configfile = File.read('config.json')
config = JSON.parse(configfile)
$region = "#{config["aws"]["DefaultRegion"]}"

# Load the AWS IP ranges and convert to a hash as a background thread.
prefetch


menuselect = 0
until menuselect == 7 do
    puts "\e[H\e[2J"
    puts "Welcome to IRSquirrel. Please select an action:"
    puts "Current region is #{$region}"
    puts ""
    puts "1. Run updated IR workflow"
    puts "2. Analyze only"
    puts "3. prefetch"
    puts "4. "
    puts "5. "
    puts "6. Change region"
    puts "7. Exit"
    puts ""
    print "Select: "
    menuselect = gets.chomp
    if menuselect == "1"
      puts "\e[H\e[2J"
      print "Enter instance ID: "
      search_item = gets.chomp
      omnisearch = OmniSearch.new(search_item)
      instance_id = omnisearch.identify_instance
      puts "Current instance ID is #{instance_id}"
      incident_response = IncidentResponse.new(instance_id)
      incident_analysis = IncidentAnalysis.new(instance_id)
      incident_response.store_metadata
      puts ""
      # even though these are displayed later in the workflow, we need to do the analysis before making changes
      autoscaling = incident_analysis.autoscale
      puts ""
      incident_analysis.assess_application
      puts ""
      # done with the analysis parts, time to change things
      incident_response.quarantine
      puts ""
      incident_response.tag
      puts ""
      incident_response.snapshot
      puts ""
      incident_response.forensics_analysis
      puts ""
      incident_analysis.analyze
      puts ""
      puts "Press Return to return to the main menu"
      blah = gets.chomp
    elsif menuselect == "2"
      puts "\e[H\e[2J"
      print "Enter instance ID, IP or DNS address, or tag: "
      search_item = gets.chomp
      omnisearch = OmniSearch.new(search_item)
      instance_id = omnisearch.identify_instance
      puts "Current instance ID is #{instance_id}"
      incident_response = IncidentResponse.new(instance_id)
      incident_analysis = IncidentAnalysis.new(instance_id)
      incident_response.store_metadata
      puts ""
      # even though these are displayed later in the workflow, we need to do the analysis before making changes
      incident_analysis.autoscale
      puts ""
      incident_analysis.assess_application
      puts ""
      incident_analysis.analyze
      puts "Press Return to return to the main menu"
      blah = gets.chomp
    elsif menuselect == "3"
      puts "\e[H\e[2J"
      prefetch
      puts "Press Return to return to the main menu"
      blah = gets.chomp
    elsif menuselect == "4"
      puts "\e[H\e[2J"
      puts "Press Return to return to the main menu"
      blah = gets.chomp
    elsif menuselect == "5"
      puts "Results of the test function:"
      puts ""
      test_function = IncidentResponse.new("12345")
      test_function.testing
      puts "Press Return to return to the main menu"
      blah = gets.chomp
    elsif menuselect == "6"
      region
    elsif menuselect == "7"
      menuselect = 7
    else 
      puts "Error, please select a valid option"
    end
end
