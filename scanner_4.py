from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
from libnmap.parser import NmapParser
import csv
import sys
import os


diffList = []

# start a new nmap scan on localhost with some specific options
def do_scan(targets, options):
    parsed = None
    nmproc = NmapProcess(targets, options)
    rc = nmproc.run()
    if rc != 0:
        print("nmap scan failed: {0}".format(nmproc.stderr))
    print(type(nmproc.stdout))
    print(nmproc.stdout)
    text_file = open("Output5.txt", "w")
    text_file.write(nmproc.stdout)
    text_file.close()

    try:
        parsed = NmapParser.parse(nmproc.stdout)
    except NmapParserException as e:
        print("Exception raised while parsing scan: {0}".format(e.msg))

    return parsed


# print scan results from a nmap report
def print_scan(nmap_report):
    print("Starting Nmap {0} ( http://nmap.org ) at {1}".format(
        nmap_report.version,
        nmap_report.started))

    for host in nmap_report.hosts:
        if len(host.hostnames):
            tmp_host = host.hostnames.pop()
        else:
            tmp_host = host.address

        print("Nmap scan report for {0} ({1})".format(
            tmp_host,
            host.address))
        print("Host is {0}.".format(host.status))
        print("  PORT     STATE         SERVICE")

        for serv in host.services:
            pserv = "{0:>5s}/{1:3s}  {2:12s}  {3}".format(
                    str(serv.port),
                    serv.protocol,
                    serv.state,
                    serv.service)
            if len(serv.banner):
                pserv += " ({0})".format(serv.banner)
            print(pserv)
    print(nmap_report.summary)


ipstring = ''
with open('test_ip.txt', newline='') as csvfile:
    iplist = list(csv.reader(csvfile))
    for row in iplist:
        ipstring = ipstring + str(row) + ','
        #print(ipstring)

#print(iplist[0])
ipstring = ipstring.replace('[', '')
ipstring = ipstring.replace(']', '')
ipstring = ipstring.replace('\'', '')
#print(ipstring)

if __name__ == "__main__":
    report = do_scan(ipstring, "-sV")
    if report:
        print_scan(report)
    else:
        print("No results returned")




def nested_obj(objname):
    rval = None
    splitted = objname.split("::")
    if len(splitted) == 2:
        rval = splitted
    return rval


def print_diff_added(obj1, obj2, added):
    global diffList
    for akey in added:
        nested = nested_obj(akey)
        if nested is not None:
            if nested[0] == 'NmapHost':
                subobj1 = obj1.get_host_byid(nested[1])
            elif nested[0] == 'NmapService':
                subobj1 = obj1.get_service_byid(nested[1])
            diffList.append("+ {0}".format(subobj1))
            print("+ {0}".format(subobj1))
        else:
            diffList.append("+ {0} {1}: {2}".format(obj1, akey, getattr(obj1, akey)))
            print("+ {0} {1}: {2}".format(obj1, akey, getattr(obj1, akey)))


def print_diff_removed(obj1, obj2, removed):
    global diffList
    for rkey in removed:
        nested = nested_obj(rkey)
        if nested is not None:
            if nested[0] == 'NmapHost':
                subobj2 = obj2.get_host_byid(nested[1])
            elif nested[0] == 'NmapService':
                subobj2 = obj2.get_service_byid(nested[1])
            diffList.append("- {0}".format(subobj2))
            print("- {0}".format(subobj2))
        else:
            diffList.append("- {0} {1}: {2}".format(obj2, rkey, getattr(obj2, rkey)))
            print("- {0} {1}: {2}".format(obj2, rkey, getattr(obj2, rkey)))


def print_diff_changed(obj1, obj2, changes):
    global diffList
    for mkey in changes:
        nested = nested_obj(mkey)
        if nested is not None:
            if nested[0] == 'NmapHost':
                subobj1 = obj1.get_host_byid(nested[1])
                subobj2 = obj2.get_host_byid(nested[1])
            elif nested[0] == 'NmapService':
                subobj1 = obj1.get_service_byid(nested[1])
                subobj2 = obj2.get_service_byid(nested[1])
            print_diff(subobj1, subobj2)
        else:
            diffList.append("~ {0} {1}: {2} => {3}".format(obj1, mkey,
                                                 getattr(obj2, mkey),
                                                 getattr(obj1, mkey)))
            print("~ {0} {1}: {2} => {3}".format(obj1, mkey,
                                                 getattr(obj2, mkey),
                                                 getattr(obj1, mkey)))



def print_diff(obj1, obj2):
    ndiff = obj1.diff(obj2)
    print_diff_changed(obj1, obj2, ndiff.changed())
    print_diff_added(obj1, obj2, ndiff.added())
    print_diff_removed(obj1, obj2, ndiff.removed())



newrep = NmapParser.parse_fromfile('Output5.txt')
oldrep = NmapParser.parse_fromfile('Output4.txt')



print_diff(newrep, oldrep)

#os.system('telegram-send "{0}"'.format(diffList[:]))

for row in diffList:
        os.system('telegram-send "{0}"'.format(row))
