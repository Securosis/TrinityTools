#!/usr/bin/env ruby

# Securitysquirrel Incident Response workflow by rmogull@securosis.com

# You must install the listed gems..
# This version is a subset of the public SecuritySquirrel code, enhancing the Incident Response workflow

# TODO list:
# Change to case/switch on the config file
# Check all variable scopes and adjust
# Automatically create the quarantine security group instead of relying on it as an option
# TODO evaluate if IAM policy to restrict IR access is set up properly and fix if it isn't
# TODO update all use of credentials to use AssumeRole
# TODO change the tagging from "IR" to pull the designated tag for the workflow from the DB
# TODO change console text output to use logger
# TODO fix to check security group for current VPC, not account/region.
# Pull the VPC based on the instance, and then alter all the calls to use the current VPC. This should also reduce the need for some config options.
# Find the forensic analysis server based on an AMI name? Then default to Amazon Linux if there isn't one.
# Change from config file to command line options as much as possible. Order should be to check for the config file, then check options
# Add begin/rescue blocks aroung AWS API calls

# need to have parameters override config file. Parameters should be instance ID, tag, quarantine group, ssh key, image id for forensics server, region
# accept an array of instances
# adjust for VPCs- detect the VPC the instance is in
# Only launch forensics server if AMI provided. Otherwise skip that step
# work for an autoscale group- isolate one instance, then wipe the rest, option to do a rolling update



require "rubygems"
require "aws-sdk"
require "json"
require 'open-uri'
require 'netaddr'
require 'logger'
require 'optparse'
require 'pry'


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
      @snap = @snap += snap.map(&:snapshot_id)
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
    creds = Aws::Credentials.new("#{creds["aws"]["AccessKey"]}", "#{creds["aws"]["SecretKey"]}")
    # Create client for EC2. May need to expand to other services later.
    ec2 = Aws::EC2::Client.new(credentials: creds, region: "#{$region}")
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

# Load the AWS IP ranges and convert to a hash as a background thread.
prefetch


# Set empty hash to hold command line options
options = {}
optparse = OptionParser.new do |opts|
	# opts.banner = "Usage: NewAccountProvisioner.rb [options] [target account arn]"
	
	options[:region] = "us-west-2"
	opts.on( '-r', '--region REGION', 'Set region. Default is us-west-2' ) do |region|
		options[:region] = region
	end
	
	options[:log] = "provisioner.log"
	opts.on( '-l', '--log LOG_DESTINATION', 'Set log destination. Enter a file name or STDOUT. Default is the file provisioner.log' ) do |log|
		options[:log] = log
	end
	
	opts.on( '-h', '--help', 'Display this screen' ) do
		puts opts
		exit
	end

# Parse the command line options
optparse.parse!
# Set the region
$region = options[:region]

# Load defaults. Right now, just the region.
configfile = File.read('config.json')
config = JSON.parse(configfile)
$region = "#{config["aws"]["DefaultRegion"]}"

# Load the AWS IP ranges and convert to a hash as a background thread.
# Do. I still need this?
prefetch

# Enable logging
if options[:log] == "STDOUT"
	$log = Logger.new(STDOUT)
else
	$log = Logger.new(options[:log], 'daily')
end

$log.info("Session started at #{Time.now}")

# Set the required variables based on the arguments. Exit if the ARN is invalid
begin
	$target_arn = ARGV.shift	
	if /arn:aws:iam::[0-9]{12}/x !~ $target_arn
		$log.error("invalid ARN provided, exiting")
		puts "Invalid ARN provided, exiting"
		exit
	elsif ($target_arn == "") or ($target_arn == nil)
		puts "No target ARN provided, exiting"
		exit
	end
rescue
	$log.error("No target ARN provided" )
	puts "No target ARN provided, exiting"
	exit
end

$log.info("ARN set to #{$target_arn}")

# Set the region
$region = options[:region]
$log.info("Region set to #{$region}")

=begin
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
=end

$log.close