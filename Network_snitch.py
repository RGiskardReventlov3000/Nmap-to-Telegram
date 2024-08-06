import string
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
import csv
import sys
import os
import time
import datetime
import telegram_send
import logging
import logging.handlers
import asyncio

# Setting up the logger
logger = logging.getLogger('NetworkSnitchLogger')
logger.setLevel(logging.DEBUG)
handler = logging.handlers.SysLogHandler(address='/dev/log')
formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Variable to record differences between scans
diffList = []

# Path to the file where the results of the new scan will be saved
currentScan = "CurrentScan.txt"
# The path to the file where the results of the old scan will be stored
prevScan = "PrevScan.txt"
# Path to file with IP list for monitoring
targetIP = 'ip.txt'

# Function to start a new nmap scan
def do_scan(targets, options):
    logger.info("Starting nmap scan for targets: {0} with options: {1}".format(targets, options))
    nmproc = NmapProcess(targets, options)
    rc = nmproc.sudo_run(run_as='root')
    if rc != 0:
        logger.error("nmap scan failed: {0}".format(nmproc.stderr))
        print("nmap scan failed: {0}".format(nmproc.stderr))
        return None

    logger.info("nmap scan completed successfully.")
    
    try:
        with open(currentScan, "w") as text_file:
            text_file.write(nmproc.stdout)
        logger.info("Scan results written to {0}".format(currentScan))
    except IOError as e:
        logger.error("Failed to write scan results to {0}: {1}".format(currentScan, e))

    try:
        parsed = NmapParser.parse(nmproc.stdout)
        logger.info("Scan results parsed successfully.")
        return parsed
    except NmapParserException as e:
        logger.error("Exception raised while parsing scan: {0}".format(e.msg))
        print("Exception raised while parsing scan: {0}".format(e.msg))
        return None

# Function to print scan results
def print_scan(nmap_report):
    logger.info("Printing scan results for Nmap report started at {0}".format(nmap_report.started))
    
    try:
        start_message = "Starting Nmap {0} ( http://nmap.org ) at {1}".format(
            nmap_report.version,
            nmap_report.started
        )
        print(start_message)
        logger.info(start_message)
    
        for host in nmap_report.hosts:
            tmp_host = host.hostnames[0] if host.hostnames else host.address

            host_message = "Nmap scan report for {0} ({1})".format(tmp_host, host.address)
            print(host_message)
            logger.info(host_message)
            
            status_message = "Host is {0}.".format(host.status)
            print(status_message)
            logger.info(status_message)
            
            print("  PORT     STATE         SERVICE")
            for serv in host.services:
                pserv = "{0:>5s}/{1:3s}  {2:12s}  {3}".format(
                    str(serv.port),
                    serv.protocol,
                    serv.state,
                    serv.service
                )
                if serv.banner:
                    pserv += " ({0})".format(serv.banner)
                print(pserv)
                logger.info("Service info: {0}".format(pserv))
                
        summary_message = nmap_report.summary
        print(summary_message)
        logger.info("Nmap report summary: {0}".format(summary_message))
    
    except Exception as e:
        logger.error("Error while printing scan results: {0}".format(e))

# Function to handle nested objects in the scan results
def nested_obj(objname):
    splitted = objname.split("::")
    return splitted if len(splitted) == 2 else None

# Function to print added differences between scans
def print_diff_added(obj1, obj2, added):
    global diffList
    logger.info("Printing added differences")
    for akey in added:
        nested = nested_obj(akey)
        if nested:
            subobj1 = obj1.get_host_byid(nested[1]) if nested[0] == 'NmapHost' else obj1.get_service_byid(nested[1])
            diff_message = "+ {0} on IP {1}".format(subobj1, obj1.id)
        else:
            diff_message = "+ {0} {1}: {2}".format(obj1, akey, getattr(obj1, akey))
        
        diffList.append(diff_message)
        print(diff_message)
        logger.info(diff_message)

# Function to print removed differences between scans
def print_diff_removed(obj1, obj2, removed):
    global diffList
    logger.info("Printing removed differences")
    for rkey in removed:
        nested = nested_obj(rkey)
        if nested:
            subobj2 = obj2.get_host_byid(nested[1]) if nested[0] == 'NmapHost' else obj2.get_service_byid(nested[1])
            diff_message = "- {0} on IP {1}".format(subobj2, obj1.id)
        else:
            diff_message = "- {0} {1}: {2}".format(obj2, rkey, getattr(obj2, rkey))
        
        diffList.append(diff_message)
        print(diff_message)
        logger.info(diff_message)

# Function to print changed differences between scans
def print_diff_changed(obj1, obj2, changes):
    global diffList
    logger.info("Printing changed differences")
    for mkey in changes:
        nested = nested_obj(mkey)
        if nested:
            subobj1 = obj1.get_host_byid(nested[1]) if nested[0] == 'NmapHost' else obj1.get_service_byid(nested[1])
            subobj2 = obj2.get_host_byid(nested[1]) if nested[0] == 'NmapHost' else obj2.get_service_byid(nested[1])
            try:
                print_diff(subobj1, subobj2)
            except AttributeError as e:
                logger.error("AttributeError in print_diff_changed: {0}".format(e))
        else:
            try:
                diff_message = "~ {0} {1}: {2} => {3}".format(obj1, mkey, getattr(obj2, mkey), getattr(obj1, mkey))
                diffList.append(diff_message)
                print(diff_message)
                logger.info(diff_message)
            except AttributeError as e:
                logger.error("AttributeError in print_diff_changed: {0}".format(e))

# Function to compare objects and print differences
def print_diff(obj1, obj2):
    logger.info("Comparing objects for differences")
    ndiff = obj1.diff(obj2)
    logger.debug("Changes detected: {0}".format(ndiff.changed()))
    logger.debug("Additions detected: {0}".format(ndiff.added()))
    logger.debug("Removals detected: {0}".format(ndiff.removed()))

    print_diff_changed(obj1, obj2, ndiff.changed())
    print_diff_added(obj1, obj2, ndiff.added())
    print_diff_removed(obj1, obj2, ndiff.removed())

# Main function to execute the scan and process the results
async def main():
    while True:
        diffList = []
        logger.info("Starting new scan cycle")
        
        try:
            ipstring = ''
            with open(targetIP, newline='') as csvfile:
                iplist = list(csv.reader(csvfile))
                ipstring = ','.join([str(row[0]) for row in iplist])

            await telegram_send.send(conf="channel2.conf", messages=["Запуск сканирования"])
            logger.info("Sent START SCAN message to Telegram")
            time.sleep(3)

            if __name__ == "__main__":
                report = do_scan(ipstring, "--min-rate 10000 -p- -n -Pn -T5")
                if report:
                    print_scan(report)
                    logger.info("Scan completed and results printed")
                else:
                    logger.warning("No results returned from scan")
                    print("No results returned")

            await telegram_send.send(conf="channel2.conf", messages=["Сканирование завершено. Отчет:"])
            logger.info("Sent SCAN END message to Telegram")
            time.sleep(2)

            # Check if prevScan exists, if not, skip comparison
            if not os.path.exists(prevScan):
                # First run: just send the current report to Telegram
                try:
                    newrep = NmapParser.parse_fromfile(currentScan)
                    rowsForSend = []

                    for host in newrep.hosts:
                        for serv in host.services:
                            pserv = "IP {0}: {1:>5s}/{2:3s}  {3:12s}  {4}".format(
                                host.address,
                                str(serv.port),
                                serv.protocol,
                                serv.state,
                                serv.service
                            )
                            if serv.banner:
                                pserv += " ({0})".format(serv.banner)
                            rowsForSend.append(pserv)

                    await telegram_send.send(conf="channel1.conf", messages=["Это первый скан. Будут отображены все открытые порты"])
                    allInOneMessage = "\n".join(rowsForSend)
                    await telegram_send.send(conf="channel1.conf", messages=[allInOneMessage])
                    logger.info("Sent current scan data to Telegram as this is the first run")

                    # Rename currentScan to prevScan
                    os.rename(currentScan, prevScan)
                    logger.info("Renamed current scan to previous scan")
                except NmapParserException as e:
                    logger.error("Exception raised while parsing scan: {0}".format(e.msg))
            else:
                # Normal mode: compare current and previous scans
                newrep = NmapParser.parse_fromfile(currentScan)
                oldrep = NmapParser.parse_fromfile(prevScan)

                print_diff(newrep, oldrep)
                logger.info("Differences between scans printed")

                rowsForSend = []

                for row in diffList:
                    if '~ NmapReport' in row and 'hosts_up:' in row:
                        rowsForSend.append("Изменилось количество хостов в сети {0}".format(row))
                    if '+ NmapHost' in row and '- up' in row:
                        rowsForSend.append("Изменилось количество сканируемых хостов {0}".format(row))
                    if '- NmapHost' in row and '- down' in row:
                        rowsForSend.append("Хост НЕ в сети {0}".format(row))
                    if '~ NmapHost' in row and 'status: down => up' in row:
                        rowsForSend.append("Хост ВЫШЕЛ на связь {0}".format(row))
                    if '~ NmapHost' in row and 'status: up => down' in row:
                        rowsForSend.append("Хост УШЕЛ со связи {0}".format(row))
                    if '+ NmapService' in row and 'open ' in row:
                        rowsForSend.append("ОТКРЫТ порт {0}".format(row))
                        time.sleep(2)
                    if '- NmapService' in row and 'filtered' not in row:
                        rowsForSend.append("ЗАКРЫТ порт {0}".format(row))

                allInOneMessage = "\n".join(rowsForSend)
                await telegram_send.send(conf="channel1.conf", messages=[allInOneMessage])
                logger.info("Sent differences to Telegram")

                # Rename currentScan to prevScan
                os.rename(currentScan, prevScan)
                logger.info("Renamed current scan to previous scan")
            
        except Exception as e:
            logger.error("An error occurred: {0}".format(e))
        
        time.sleep(5)

# Start the main loop
asyncio.run(main())
