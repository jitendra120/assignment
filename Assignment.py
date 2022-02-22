#!/usr/bin/python
# Converted from VPC_With_VPN_Connection.template located at:
# http://aws.amazon.com/cloudformation/aws-cloudformation-templates

from troposphere import (
    Base64,
    FindInMap,
    GetAtt,
    Join,
    Output,
    GetAtt,
    Parameter,
    Ref,
    Tags,
    Template,
)
from troposphere.autoscaling import Metadata
from troposphere.cloudformation import (
    Init,
    InitConfig,
    InitFile,
    InitFiles,
    InitService,
    InitServices,
)
from troposphere.ec2 import (
    EIP,
    VPC,
    ec2,
    Instance,
    InternetGateway,
    NetworkAcl,
    NetworkAclEntry,
    NetworkInterfaceProperty,
    PortRange,
    Route,
    RouteTable,
    SecurityGroup,
    SecurityGroupRule,
    Subnet,
    SubnetNetworkAclAssociation,
    SubnetRouteTableAssociation,
    VPCGatewayAttachment,
)
from troposphere.policies import CreationPolicy, ResourceSignal
import troposphere.elasticloadbalancingv2 as elb


t = Template()

t.set_version("2022-01-21")

t.set_description(
    """\
 This Python Code will create cloudformation template with below details \   
 1 Create VPC with private and public subnet \
 2 Create Two Security Group
 3 Create ALB in public subnet   \
 4 Create EC2 Instance in private subnet \
 ."""
)

keyname_param = t.add_parameter(
    Parameter(
        "computekey.pem",
        ConstraintDescription="must be the name of an existing EC2 KeyPair.",
        Description="Name of an existing EC2 KeyPair to enable SSH access to \
the instance",
        Type="AWS::EC2::KeyPair::computekey.pem",
    )
)

sshlocation_param = t.add_parameter(
    Parameter(
        "SSHLocation",
        Description=" The IP address range that can be used to SSH to the EC2 instances",
        Type="String",
        MinLength="9",
        MaxLength="18",
        Default="0.0.0.0/0",
        AllowedPattern=r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})",
        ConstraintDescription=("must be a valid IP CIDR range of the form x.x.x.x/x."),
    )
)

instanceType_param = t.add_parameter(
    Parameter(
        "InstanceType",
        Type="String",
        Description="WebServer EC2 instance type",
        Default="t2.micro",
        AllowedValues=[
            "t2.micro",
        ],
        ConstraintDescription="must be a valid EC2 instance type.",
    )
)

t.add_mapping(
    "AWSInstanceType2Arch",
    {
        "t2.micro": {"Arch": "HVM64"},
    },
)

t.add_mapping(
    "AWSRegionArch2AMI",
    {
        "us-east-1": {
            "PV64": "ami-50842d38",
            "HVM64": "ami-08842d60",
            "HVMG2": "ami-3a329952",
        },
        "us-west-2": {
            "PV64": "ami-af86c69f",
            "HVM64": "ami-8786c6b7",
            "HVMG2": "ami-47296a77",
        },
        "us-west-1": {
            "PV64": "ami-c7a8a182",
            "HVM64": "ami-cfa8a18a",
            "HVMG2": "ami-331b1376",
        },
        "eu-west-1": {
            "PV64": "ami-aa8f28dd",
            "HVM64": "ami-748e2903",
            "HVMG2": "ami-00913777",
        },
        "ap-southeast-1": {
            "PV64": "ami-20e1c572",
            "HVM64": "ami-d6e1c584",
            "HVMG2": "ami-fabe9aa8",
        },
        "ap-northeast-1": {
            "PV64": "ami-21072820",
            "HVM64": "ami-35072834",
            "HVMG2": "ami-5dd1ff5c",
        },
        "ap-southeast-2": {
            "PV64": "ami-8b4724b1",
            "HVM64": "ami-fd4724c7",
            "HVMG2": "ami-e98ae9d3",
        },
        "sa-east-1": {
            "PV64": "ami-9d6cc680",
            "HVM64": "ami-956cc688",
            "HVMG2": "NOT_SUPPORTED",
        },
        "cn-north-1": {
            "PV64": "ami-a857c591",
            "HVM64": "ami-ac57c595",
            "HVMG2": "NOT_SUPPORTED",
        },
        "eu-central-1": {
            "PV64": "ami-a03503bd",
            "HVM64": "ami-b43503a9",
            "HVMG2": "ami-b03503ad",
        },
    },
)

ref_stack_id = Ref("AWS::788727463290")
ref_region = Ref("AWS::us-east-1")
ref_stack_name = Ref("AWS::DemoStack")

VPCResource = t.add_resource(
    VPC("VPC", CidrBlock="10.0.0.0/16", Tags=Tags(Application=ref_stack_id))
)

######################### Start Private Subnet #########################
private_subnet = t.add_parameter(
    Parameter(
        "10.0.10.0/16",
        Type="String",
        Description="Public Subnet CIDR",
        Default="10.0.10.0/16",
    )
)
######################### End Private Subnet #########################

######################### Start Public Subnet #########################

public_subnet = t.add_parameter(
    Parameter(
        "10.0.11.0/16",
        Type="String",
        Description="Public Subnet CIDR",
        Default="10.0.11.0/16",
    )
)

######################### End public Subnet #########################

## Create Internet Gateway for Public Subnet
internetGateway = t.add_resource( 
    InternetGateway("InternetGateway", Tags=Tags(Application=ref_stack_id))
)

net_gw_vpc_attachment = t.add_resource(
    ec2.VPCGatewayAttachment(
        "NatAttachment",
        VpcId=Ref(vpc),
        InternetGatewayId=Ref(internetGateway),
    )
)




gatewayAttachment = t.add_resource(
    VPCGatewayAttachment(VPCResource
        "AttachGateway", VpcId=Ref(VPCResource), InternetGatewayId=Ref(internetGateway)
    )
)

routeTable = t.add_resource(
    RouteTable(
        "RouteTable", VpcId=Ref(VPCResource), Tags=Tags(Application=ref_stack_id)
    )
)

route = t.add_resource(
    Route(
        "Route",
        DependsOn="AttachGateway",
        GatewayId=Ref("InternetGateway"),
        DestinationCidrBlock="0.0.0.0/0",
        RouteTableId=Ref(routeTable),
    )
)

subnetRouteTableAssociation = t.add_resource(
    SubnetRouteTableAssociation(
        "SubnetRouteTableAssociation",
        SubnetId=Ref(private_subnet),
        RouteTableId=Ref(routeTable),
    )
)

networkAcl = t.add_resource(
    NetworkAcl(
        "NetworkAcl",
        VpcId=Ref(VPCResource),
        Tags=Tags(Application=ref_stack_id),
    )
)

inBoundPrivateNetworkAclEntry = t.add_resource(
    NetworkAclEntry(
        "InboundHTTPNetworkAclEntry",
        NetworkAclId=Ref(networkAcl),
        RuleNumber="100",
        Protocol="6",
        PortRange=PortRange(To="80", From="80"),
        Egress="false",
        RuleAction="allow",
        CidrBlock="0.0.0.0/0",
    )
)

inboundSSHNetworkAclEntry = t.add_resource(
    NetworkAclEntry(
        "InboundSSHNetworkAclEntry",
        NetworkAclId=Ref(networkAcl),
        RuleNumber="101",
        Protocol="6",
        PortRange=PortRange(To="22", From="22"),
        Egress="false",
        RuleAction="allow",
        CidrBlock="0.0.0.0/0",
    )
)

inboundResponsePortsNetworkAclEntry = t.add_resource(
    NetworkAclEntry(
        "InboundResponsePortsNetworkAclEntry",
        NetworkAclId=Ref(networkAcl),
        RuleNumber="102",
        Protocol="6",
        PortRange=PortRange(To="65535", From="1024"),
        Egress="false",
        RuleAction="allow",
        CidrBlock="0.0.0.0/0",
    )
)

outBoundHTTPNetworkAclEntry = t.add_resource(
    NetworkAclEntry(
        "OutBoundHTTPNetworkAclEntry",
        NetworkAclId=Ref(networkAcl),
        RuleNumber="100",
        Protocol="6",
        PortRange=PortRange(To="80", From="80"),
        Egress="true",
        RuleAction="allow",
        CidrBlock="0.0.0.0/0",
    )
)

outBoundHTTPSNetworkAclEntry = t.add_resource(
    NetworkAclEntry(
        "OutBoundHTTPSNetworkAclEntry",
        NetworkAclId=Ref(networkAcl),
        RuleNumber="101",
        Protocol="6",
        PortRange=PortRange(To="443", From="443"),
        Egress="true",
        RuleAction="allow",
        CidrBlock="0.0.0.0/0",
    )
)

outBoundResponsePortsNetworkAclEntry = t.add_resource(
    NetworkAclEntry(
        "OutBoundResponsePortsNetworkAclEntry",
        NetworkAclId=Ref(networkAcl),
        RuleNumber="102",
        Protocol="6",
        PortRange=PortRange(To="65535", From="1024"),
        Egress="true",
        RuleAction="allow",
        CidrBlock="0.0.0.0/0",
    )
)

subnetNetworkAclAssociation = t.add_resource(
    SubnetNetworkAclAssociation(
        "SubnetNetworkAclAssociation",
        SubnetId=Ref(private_subnet),
        NetworkAclId=Ref(networkAcl),
    )
)

instanceSecurityGroup = t.add_resource(
    SecurityGroup(
        "InstanceSecurityGroup",
        GroupDescription="Enable SSH access via port 22",
        SecurityGroupIngress=[
            SecurityGroupRule(
                IpProtocol="tcp",
                FromPort="22",
                ToPort="22",
                CidrIp=Ref(sshlocation_param),
            ),
            SecurityGroupRule(
                IpProtocol="tcp", FromPort="80", ToPort="80", CidrIp="0.0.0.0/0"
            ),
        ],
        VpcId=Ref(VPCResource),
    )
)

################### Create ALB in public subnet ########################################
    alb = template.add_resource(
        elb.LoadBalancer(
            "ALB",
            Scheme="internet-facing",
            Subnets=[public_subnet.ref()],
        )
    )

    listener = template.add_resource(
        elb.Listener(
            "Listener",
            Port="80",
            Protocol="HTTP",
            LoadBalancerArn=alb.ref(),
            DefaultActions=[
                elb.Action(
                    Type="fixed-response",
                    FixedResponseConfig=elb.FixedResponseConfig(
                        StatusCode="200",
                        MessageBody=(
                            "This is a fixed response for the default " "ALB action"
                        ),
                        ContentType="text/plain",
                    ),
                )
            ],
        )
    )

    template.add_resource(
        [
            elb.ListenerRule(
                "ListenerRuleApi",
                ListenerArn=listener.ref(),
                Conditions=[
                    elb.Condition(Field="host-header", Values=["api.example.com"]),
                    elb.Condition(
                        Field="http-header",
                        HttpHeaderConfig=elb.HttpHeaderConfig(
                            HttpHeaderName="X-Action", Values=["Create"]
                        ),
                    ),
                    elb.Condition(
                        Field="path-pattern",
                        PathPatternConfig=elb.PathPatternConfig(Values=["/api/*"]),
                    ),
                    elb.Condition(
                        Field="http-request-method",
                        HttpRequestMethodConfig=elb.HttpRequestMethodConfig(
                            Values=["POST"]
                        ),
                    ),
                ],
                Actions=[
                    elb.ListenerRuleAction(
                        Type="fixed-response",
                        FixedResponseConfig=elb.FixedResponseConfig(
                            StatusCode="200",
                            MessageBody=(
                                "This is a fixed response for any API POST "
                                "request with header X-Action: Create"
                            ),
                            ContentType="text/plain",
                        ),
                    )
                ],
                Priority="10",
            ),
            elb.ListenerRule(
                "ListenerRuleWeb",
                ListenerArn=listener.ref(),
                Conditions=[
                    elb.Condition(
                        Field="host-header",
                        HostHeaderConfig=elb.HostHeaderConfig(
                            Values=["www.example.com"]
                        ),
                    ),
                    elb.Condition(
                        Field="path-pattern",
                        PathPatternConfig=elb.PathPatternConfig(Values=["/web/*"]),
                    ),
                ],
                Actions=[
                    elb.ListenerRuleAction(
                        Type="fixed-response",
                        FixedResponseConfig=elb.FixedResponseConfig(
                            StatusCode="200",
                            MessageBody=(
                                "This is a fixed response for any WEB " "request"
                            ),
                            ContentType="text/plain",
                        ),
                    )
                ],
                Priority="20",
            ),
            elb.ListenerRule(
                "ListenerRuleMetrics",
                ListenerArn=listener.ref(),
                Conditions=[elb.Condition(Field="path-pattern", Values=["/metrics/*"])],
                Actions=[
                    elb.ListenerRuleAction(
                        Type="redirect",
                        RedirectConfig=elb.RedirectConfig(
                            StatusCode="HTTP_301", Protocol="HTTPS", Port="443"
                        ),
                    )
                ],
                Priority="30",
            ),
            elb.ListenerRule(
                "ListenerRuleSourceIp",
                ListenerArn=listener.ref(),
                Conditions=[
                    elb.Condition(
                        Field="source-ip",
                        SourceIpConfig=elb.SourceIpConfig(Values=["52.30.12.16/28"]),
                    )
                ],
                Actions=[
                    elb.ListenerRuleAction(
                        Type="fixed-response",
                        FixedResponseConfig=elb.FixedResponseConfig(
                            StatusCode="200",
                            MessageBody=(
                                "The request came from IP range " "52.30.12.16/28"
                            ),
                            ContentType="text/plain",
                        ),
                    )
                ],
                Priority="40",
            ),
        ]
    )
############################ END ALB ############################




##################  Create Auto Scalling Group   ##################
ScaleCapacity = t.add_parameter(
    Parameter(
        "ScaleCapacity",
        Default="1",
        Type="String",
        Description="Number of api servers to run",
    )
)




## ad Launch configuration for ASG
LaunchConfig = t.add_resource(
    LaunchConfiguration(
        "LaunchConfiguration",
        Metadata=autoscaling.Metadata(
            cloudformation.Init(
                {
                    "config": cloudformation.InitConfig(
                        files=cloudformation.InitFiles(
                            {
                                "/etc/rsyslog.d/20-somethin.conf": cloudformation.InitFile(
                                    source=Join(
                                        "",
                                        [
                                            "http://",
                                            Ref(DeployBucket),
                                            ".s3.amazonaws.com/stacks/",
                                            Ref(RootStackName),
                                            "/env/etc/rsyslog.d/20-somethin.conf",
                                        ],
                                    ),
                                    mode="000644",
                                    owner="root",
                                    group="root",
                                    authentication="DeployUserAuth",
                                )
                            }
                        ),
                        services={
                            "sysvinit": cloudformation.InitServices(
                                {
                                    "rsyslog": cloudformation.InitService(
                                        enabled=True,
                                        ensureRunning=True,
                                        files=["/etc/rsyslog.d/20-somethin.conf"],
                                    )
                                }
                            )
                        },
                    )
                }
            ),
            cloudformation.Authentication(
                {
                    "DeployUserAuth": cloudformation.AuthenticationBlock(
                        type="S3",
                        accessKeyId=Ref(DeployUserAccessKey),
                        secretKey=Ref(DeployUserSecretKey),
                    )
                }
            ),
        ),
        UserData=Base64(
            Join(
                "",
                [
                    "#!/bin/bash",
                    "\n",
                    "sudo apt-get update\n",
                    "sudo apt-get install -y nginx\n",
                    "sudo service nginx start\n",
                    "\n",
                    "cat > /var/www/html/index.html << \"EOF\"\n",
                    "<title>Cloud formation Nginx server</title>\n",
                    "<h1>Name</h1><p>This is a demo nginx server created for demo",
                    {
                      "Ref": "jitendra chouhan"
                    },
                    "</p>\n",
                    "EOF\n",
                    "\n"
                ]
        ),
        ImageId=Ref(AmiId),
        KeyName=Ref(KeyName),
        BlockDeviceMappings=[
            BlockDeviceMapping(
                DeviceName="/dev/sda1", Ebs=EBSBlockDevice(VolumeSize="8")
            ),
        ],
        SecurityGroups=[Ref(SecurityGroup)],
        InstanceType="m1.small",
    )
)

LoadBalancerResource = t.add_resource(
    LoadBalancer(
        "LoadBalancer",
        ConnectionDrainingPolicy=elb.ConnectionDrainingPolicy(
            Enabled=True,
            Timeout=120,
        ),
        Subnets=[Ref(private_subnet)],
        HealthCheck=elb.HealthCheck(
            Target="HTTP:80/",
            HealthyThreshold="5",
            UnhealthyThreshold="2",
            Interval="20",
            Timeout="15",
        ),
        Listeners=[
            elb.Listener(
                LoadBalancerPort="443",
                InstancePort="80",
                Protocol="HTTPS",
                InstanceProtocol="HTTP",
                SSLCertificateId=Ref(SSLCertificateId),
            ),
        ],
        CrossZone=True,
        SecurityGroups=[Ref(LoadBalancerSecurityGroup)],
        LoadBalancerName="api-lb",
        Scheme="internet-facing",
    )
)

AutoscalingGroup = t.add_resource(
    AutoScalingGroup(
        "AutoscalingGroup",
        DesiredCapacity=Ref(ScaleCapacity),
        Tags=[Tag("Environment", Ref(EnvType), True)],
        LaunchConfigurationName=Ref(LaunchConfig),
        MinSize=Ref(ScaleCapacity),
        MaxSize=Ref(ScaleCapacity),
        VPCZoneIdentifier=[Ref(private_subnet)],
        LoadBalancerNames=[Ref(LoadBalancerResource)],
        HealthCheckType="EC2",
        UpdatePolicy=UpdatePolicy(
            AutoScalingReplacingUpdate=AutoScalingReplacingUpdate(
                WillReplace=True,
            ),
            AutoScalingRollingUpdate=AutoScalingRollingUpdate(
                PauseTime="PT5M",
                MinInstancesInService="1",
                MaxBatchSize="1",
                WaitOnResourceSignals=True,
            ),
        ),
    )
)
##################  END Auto Scalling Group   ##################

ipAddress = t.add_resource(
    EIP("IPAddress", DependsOn="AttachGateway", Domain="vpc", InstanceId=Ref(instance))
)

t.add_output(
    [
        Output(
            "URL",
            Description="Newly created application URL",
            Value=Join("", ["http://", GetAtt("WebServerInstance", "PublicIp")]),
        )
    ]
)

print(t.to_json())