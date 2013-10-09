#!/usr/bin/python

import re
import sys
import ssl
import M2Crypto
import socket
from datetime import datetime 
import nmap

# TODO: Check for validity of the chain: 
#   * Trusted CAs
#   * Expired certificates for the CAs
#   * Summary of the CAs in a column

# TODO: Establecer estadisticas del tipo de informacion que tienen los top sites
# Usar la API de dev.compete.com (pasarsela como argumento al programa)
# Mostrara la clasificacion de los sitios de internet y que mercados son mas seguros que otros en temas de certificados y comunicaciones cifradas..

#############
# FUNCTIONS #
#############

# Timeout function taken from http://stackoverflow.com/questions/492519/timeout-on-a-python-function-call
# (Thanks FSM exists stackoverflow.com)
def timeout(func, args=(), kwargs={}, timeout_duration=10, default=None):
    """This function will spawn a thread and run the given function
    using the args, kwargs and return the given default value if the
    timeout_duration is exceeded.
    """ 
    import threading
    class InterruptableThread(threading.Thread):
        def __init__(self):
            threading.Thread.__init__(self)
            self.result = default
        def run(self):
            self.result = func(*args, **kwargs)
    it = InterruptableThread()
    it.start()
    it.join(timeout_duration)
    if it.isAlive():
        return it.result
    else:
        return it.result
    
def retrieveSiteCertificate(ip,port):
    retrievedcert = None
    exception = None
    ssl.PROTOCOL_SSLv23
    
    try:
        retrievedcert=ssl.get_server_certificate((ip, int(port)),ssl_version=ssl.PROTOCOL_SSLv23)
    except ssl.SSLError:
        try:
            # TODO: Confirmar si ssl.PROTOCOL_TLSv1 cambia el protocolo 8NO ES FUNCION)
            print "Server %s not accepting SSLv2 neither SSLv3. Changing to TLSv1..." % ip_or_domain
            retrievedcert=ssl.get_server_certificate((ip, int(port)),ssl_version=ssl.PROTOCOL_TLSv1)
        
        except Exception as generale1:
            exception=generale1
                
    except Exception as generale2:
        exception=generale2
    
    return retrievedcert,exception

def isTargetPortOpen(ip,port):
    return True
    print "Scannig port %s:%s" % (ip,port)
    nm = nmap.PortScanner()
    scanresult = nm.scan(ip,port)
    print nm.command_line()
    return (scanresult['scan'][ip]['status']['state'] == 'up' and scanresult['scan'][ip]['tcp'][int(port)]['state'] == 'open')

def isCertificateTimeValid(not_after,not_before):
    # Date in format Sep 11 10:50:21 2014 GMT
    return (datetime.today() < datetime.strptime(not_after,'%b %d %H:%M:%S %Y %Z') and datetime.today() > datetime.strptime(not_before,'%b %d %H:%M:%S %Y %Z'))

# TODO: Add checking for wildcards like "*"
def validCNForDomainName(domain,cn):
    domain = domain.strip()
    cn = cn.strip()
    cn = cn.replace(".","\.")
    cn = cn.replace("*",".*")
    cnre = re.compile(cn)
    matchcn = cnre.match(domain)
    return matchcn is not None and matchcn.group(0)==domain

def domainToIp(domain):
    ip = domain
    if not re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',domain):
        try:
            ip=socket.gethostbyname(domain)
        except Exception as e:
            pass

    return ip

def getSignatureAlgorithm(cert_X509):
    pKeyAlgorithm = "<NOT FOUND>"
    matches = re.search('Signature Algorithm:\s+(.*)',cert_X509.as_text())
    if matches is not None and matches.group(1) is not None:
        pKeyAlgorithm = matches.group(1)
    return pKeyAlgorithm
    # + ";"  # Public Key Algorithm: rsaEncryption
       
def getPublicKeyAlgorithm(cert_X509):
    pubKeyAlgorithm = "<NOT FOUND>"
    matches = re.search('Public Key Algorithm:\s+(.*)',cert_X509.as_text())
    if matches is not None and matches.group(1) is not None:
        pubKeyAlgorithm = matches.group(1)
    return pubKeyAlgorithm
    # Public Key Algorithm: rsaEncryption
    
def getPublicKeySize(cert_X509):
    pubKeySize = "<NOT FOUND>"
    matches = re.search('Public-Key:\s+\((.*) bit\)',cert_X509.as_text())
    if matches is not None and matches.group(1) is not None:
        pubKeySize = matches.group(1)
    return pubKeySize
    # Public-Key: (2048 bit)


########
# MAIN #
########

# Check mandatory arguments
if len(sys.argv) != 3:
    print "Usage: %s <IP:PORT List file> <Output file CSV>"
    exit(1)

# Get the list of IPs with https service
inputfile=sys.argv[1]
outputfile=sys.argv[2]

try:
    ifile=open(inputfile,"r")
except IOError:
    sys.stderr.write("Error. There was some problem opening '%s' input file.\n" % inputfile)
    exit(1)

try:    
    ofile=open(outputfile,"w")
except IOError:
    sys.stderr.write("Error. There was some problem opening '%s' output CSV.\n" % outputfile)
    exit(1)

# Add header to CSV File
ofile.write("Domain;IP;Port;Time Expired;Correct CN;Signature Algorithm;Public Key Algorithm;Public Key Size;Subject CN;Subject C;Subject ST;Subject L;Subject O;Subject OU;Subject Email;Valid not after;Valid not before;Serial Number;Version;Issuer ST;Issuer C;Issuer L;Issuer O;Issuer OU;Issuer CN;\n")

nline=0
for iline in ifile:
    nline+=1
    iline=iline.strip()
    # If this line is not a commentary (marked with a '#')
    if iline[0]!='#':
        ip_port=iline.split(":")
        if len(ip_port) == 1 or len(ip_port) == 2:
            ip_or_domain=ip_port[0] 
            port=443
            if len(ip_port) == 2:
                port=int(ip_port[1])
    
            ip = domainToIp(ip_or_domain)
            if (not re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',ip)):
                sys.stderr.write("Line %s: The IP '%s' does not have a correct format. Skipping...\n" % (nline,iline))
                continue
            if (port < 1 or port > 65534):
                sys.stderr.write("Line %s: The port %s is out of bounds (1-65535). Skipping...\n" % (nline,port))
                continue
           
            if (isTargetPortOpen(ip,port)):
                # Get all the certificate information we can
                print ("Getting certificate info from %s:%s (%s)") % (ip,port,ip_or_domain)
                cert,exception=retrieveSiteCertificate(ip,port)
                
                if exception is not None:
                    sys.stderr.write("Line %s: There was some problem retrieving the certificate of %s (%s). Skipping...\n" % (nline,ip_or_domain,ip))
                    ofile.write("%s;%s;%s;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;\n" % (ip_or_domain,ip,port))
                    continue
                
                if cert is None:
                    sys.stderr.write("Line %s: Timeout while retrieving the certificate of %s (%s). Skipping...\n" % (nline,ip_or_domain,ip))
                    ofile.write("%s;%s;%s;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;\n" % (ip_or_domain,ip,port))
                    continue

                cert_X509=M2Crypto.X509.load_cert_string(cert)
                #Escribimos los datos
                ofile.write(ip_or_domain + ";")
                ofile.write(ip + ";")
                ofile.write(str(port) + ";")
                if isCertificateTimeValid(str(cert_X509.get_not_after()),str(cert_X509.get_not_before())):
                    ofile.write("OK;")
                else:
                    ofile.write("FAIL;")

                if validCNForDomainName(ip_or_domain,str(cert_X509.get_subject().CN)):
                    ofile.write("OK;")
                else:
                    ofile.write("FAIL;")
                # Obtenemos algunos datos del texto del certificado
                # TODO: Parsear texto es un poco cutre, pero no he encontrado las propiedades que busco en la clase X509 facilmente
                ofile.write(getSignatureAlgorithm(cert_X509) + ";")
                ofile.write(getPublicKeyAlgorithm(cert_X509) + ";")
                ofile.write(getPublicKeySize(cert_X509) + ";")      
                ofile.write(str(cert_X509.get_subject().CN) + ';')
                ofile.write(str(cert_X509.get_subject().C) + ';')
                ofile.write(str(cert_X509.get_subject().ST) + ';')
                ofile.write(str(cert_X509.get_subject().L) + ';')
                ofile.write(str(cert_X509.get_subject().O) + ';')
                ofile.write(str(cert_X509.get_subject().OU) + ';')
                ofile.write(str(cert_X509.get_subject().emailAddress) + ';')
                ofile.write(str(cert_X509.get_not_after()) + ';')
                ofile.write(str(cert_X509.get_not_before()) + ';')
                ofile.write(str(cert_X509.get_serial_number()) + ';')
                ofile.write(str(cert_X509.get_version()) + ';')
                ofile.write(str(cert_X509.get_issuer().ST) + ';')
                ofile.write(str(cert_X509.get_issuer().C) + ';')
                ofile.write(str(cert_X509.get_issuer().L) + ';')
                ofile.write(str(cert_X509.get_issuer().O) + ';')
                ofile.write(str(cert_X509.get_issuer().OU) + ';')
                ofile.write(str(cert_X509.get_issuer().CN) + ';')
                ofile.write("\n")
            else:  # Del isTargetPortOpen
                print sys.stderr.write("Line %s: Target port %s is not open on target domain host (%s,%s). Skipping...\n" % (nline,port,ip_or_domain,ip))
                ofile.write("%s;%s;%s;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;NOT AVAILABLE;\n" % (ip_or_domain,ip,port))
        else:
            sys.stderr.write("Line %s: The IP does not have the format <IP>:<PORT>. Skipping...\n" % nline)
    else: # Es un comentario
        print "Line %s: This line is a commentary (%s). Ignoring" % (nline,iline)

ifile.close()
ofile.close()

