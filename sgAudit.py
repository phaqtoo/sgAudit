import boto.ec2
import hashlib

try:
    conn = boto.ec2.connect_to_region("us-west-2")
    current_sgs = conn.get_all_security_groups()
except boto.exception.BotoServerError, e:log.error(e.error_message)

conn.close()

for sg in current_sgs:
    print "="*80
    print "ID:\t\t", sg.id
    print "Name:\t\t", sg.name
    print "VPC:\t\t", sg.vpc_id
    print "Instance ID:\t", sg.instances()
    print "Ingress Rules:"
    for rule in sg.rules:
        ruledata = sg.id,rule.grants,rule.ip_protocol,rule.from_port,rule.to_port,"Ingress"
        rulehash=hashlib.sha256(str(ruledata)).hexdigest()
        print "\thash:",rulehash
        print "\t",rule.grants,"-> [Instance]:",rule.from_port,"-",rule.to_port,rule.ip_protocol
    
    print "Egress Rules:"
    for rule in sg.rules_egress:
        ruletuple = sg.id,rule.grants,rule.ip_protocol,rule.from_port,rule.to_port,"Egress"
        rulehash=hashlib.sha256(str(ruletuple)).hexdigest()
        print "\thash:",rulehash
        print "\t[Instance]->",rule.grants,":",rule.from_port,"-",rule.to_port,rule.ip_protocol
