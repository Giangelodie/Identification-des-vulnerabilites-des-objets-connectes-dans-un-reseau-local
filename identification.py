import pyshark as ps
from json import *
from subprocess import *
from search_os import *
import time
from lxml import etree as ET
from requests import *

def list_mac(cap, access_p):
    """
    Fonction qui liste toutes les adresses MAC présentes dans
    la capture.

    Parameters
    ----------
    cap : Liste des trames de la capture.
    access_p : Adresse MAC du point d'accès.

    Returns
    -------
    Liste d'adresses MAC.

    """
    M = []
    for pkt in cap:
        dst = pkt.eth.dst
        src = pkt.eth.src
        if dst not in M and dst != access_p:
            M += [dst]
        if src not in M and src != access_p:
            M += [src]
    return(M)


def list_couple(cap, access_p):
    """
    Fonction qui liste tout les couples adresse MAC/adresse IP présentes dans
    la capture.

    Parameters
    ----------
    cap : Liste des trames de la capture.
    access_p : Adresse MAC du point d'accès.

    Returns
    -------
    Liste reçue en paramètre incrémentée des adresses IP.

    """
    L = []
    for pkt in cap:
        dst = [pkt.eth.dst, ['ip', pkt[1].dst]]
        src = [pkt.eth.src, ['ip', pkt[1].src]]
        if dst not in L and dst[0] != access_p:
            L += [dst]
        if src not in L and src[0] != access_p:
            L += [src]
    return(L)


def list_obj(cap, access_p):
    """
    Fonction qui créée une liste de toutes les adresses MAC associées à leurs
    adresses IP.

    Parameters
    ----------
    cap : Liste des trames de la capture.
    access_p : Adresse MAC du point d'accès.

    Returns
    -------
    Liste d'adresses MAC associées à leurs adresses IP.

    """
    C = []
    M = list_mac(cap, access_p)
    L = list_couple(cap, access_p)
    for add in M:
        tmp = [add]
        i = 0
        while i < len(L):
            if add == L[i][0]:
                tmp += [L[i][1]]
            i += 1
        C += [tmp]
    return(C)


def list_op_dhcp(cap, L, access_p):
    """
    Fonction qui associe aux appareils leur champ HostName du protocole DHCP si
    ils en ont émis. Liste les HostName des appareils WIFI dans une nouvelle
    liste.

    Parameters
    ----------
    cap : Liste des trames DHCP de la capture.
    L : Liste des appareils Ethernets
    access_p : Adresse MAC du point d'accès.

    Returns
    -------
    Liste des appareils associés à leur HostName ainsi que la liste des Hostname
    des appareils WIFI.

    """
    done = []
    dhcp = []
    for pkt in cap:     # On parcours l'intégralité des trames dhcp de la capture.
        try:
            if access_p == pkt.bootp.hw_mac_addr and pkt.bootp.option_hostname not in dhcp:     # Si cette trame provient du point d'accès et que nous
                dhcp += [['hn', pkt.bootp.option_hostname]]                                     # avons pas encore croisé cet Host Name, on le stoque.
            else:
                for i in L:     # on parcours la liste de nos appareils
                    if i[0] not in done and i[0] == pkt.bootp.hw_mac_addr:      # On cherche de quel appareil cette trame provient en comparant
                        i += [['hn', pkt.bootp.option_hostname]]                # les adresses MAC puis on ajoute l'Host Name à son appareil.
                        done += [pkt.bootp.hw_mac_addr]                         # Nous stockons les appareils déjà identifié pour ne pas les refaire.
                        break
        except AttributeError:      # try/except qui permet d'ignorer les trames contenant pas de Host Name.
            pass
    return L, dhcp


def list_info_http(cap, L, access_p):
    """
    Fonction qui associe aux appareils leur champ User-Agent du protocole HTTP
    si ils en ont émis. Liste les User-Agent des appareils WIFI dans une
    nouvelle liste.

    Parameters
    ----------
    cap : Liste des trames HTTP de la capture.
    L : Liste des appareils Ethernets
    access_p : Adresse MAC du point d'accès.

    Returns
    -------
    Liste des appareils associés à leur User-Agent ainsi que la liste des
    User-Agent des appareils WIFI.

    """
    done = []
    http = []
    for pkt in cap:
        try:
            if access_p == pkt.eth.src and pkt.http.user_agent not in http:
                http += [pkt.http.user_agent]
            else:
                for i in L:
                    if i[0] not in done and i[0] == pkt.eth.src:
                        if ['UA', pkt.http.user_agent] not in i:
                            i += [['UA', pkt.http.user_agent]]
                        break
        except AttributeError:
            pass
    return L, http


def extract(xml):
    L_info = ['{urn:schemas-upnp-org:device-1-0}MACAddress', '{urn:schemas-upnp-org:device-1-0}modelName',
              '{urn:schemas-upnp-org:device-1-0}manufacturer', '{urn:schemas-upnp-org:device-1-0}deviceType',
              '{urn:schemas-upnp-org:device-1-0}modelDescription']
    #liste des infos dont on a besoin, MAC, Nom du model, le vendeur, le type, La description
    try :
        file = get(xml)
    except :
        return None
    Ldevice = []
    with open("device.xml", "w") as f:
        f.write("{file.text}")
    local_input = "device.xml"
    p = ET.XMLParser(recover=True)
    tree = ET.parse(local_input, parser=p)
    root = tree.getroot()
    for child in root:
        if child.tag == '{urn:schemas-upnp-org:device-1-0}device':
            for i in L_info:
                for c in child:
                    if c.tag == i:
                        Ldevice.append(c.text) #on met dans la liste de l'objet tous les éléments qui nous intéresse en fonction de L_info
    return Ldevice


def list_info_ssdp(cap, L, access_p):
    """
    Fonction qui associe aux appareils les informations contenues dans le
    fichier XMLtrouvé dans le protocole SSDP si ils en ont émis. Liste les
    informations des appareils WIFI dans une nouvelle liste.

    Parameters
    ----------
    cap : Liste des trames SSDP de la capture.
    L : Liste des appareils Ethernets.
    access_p : Adresse MAC du point d'accès.

    Returns
    -------
    Liste des appareils associés à leurs informations ainsi que la liste des
    informations des appareils WIFI.

    """
    done = []
    Lssdp = []
    for pkt in cap:
        try:
            tmp = [['ssdp', pkt.ssdp.http_location, extract(pkt.ssdp.http_location)]]
            if tmp[0][2] != None:
                for i in L:
                    if access_p == pkt.eth.src and tmp not in Lssdp:
                        Lssdp += tmp
                    else:
                        if i[0] not in done and i[0] == pkt.eth.src:
                            i += tmp
                            done += [pkt.eth.src]
                            break
        except AttributeError:
            pass
    return L, Lssdp



# def get_data(fic):
#     """
#     Fonction qui extrait les informations d'un fichier JSON.
#
#     Parameters
#     ----------
#     fic : Fichier JSON.
#
#     Returns
#     -------
#     Liste des appareils associés à leur User-Agent ainsi que la liste des
#     User-Agent des appareils WIFI.
#
#     """
#     with open(fic) as f:
#         data = load(f)
#     return data


def construct():
    """
    Fonction qui extrait les informations du fichier 'macaddress.io-db.json'.

    Parameters
    ----------
    None.

    Returns
    -------
    Liste des informations contenues dans le fichier 'macaddress.io-db.json'.

    """
    data = []
    for line in open('macaddress.io-db.json', 'r', encoding='utf-8'):
        data.append(loads(line))
    return data


def supp_MAC(L):
    """
    Fonction qui supprime les adresses MAC inintéressantes tel que les adresses
    Broadcast.

    Parameters
    ----------
    L : Liste d'adresses MAC.

    Returns
    -------
    Liste des adresses MAC qui identifient des appareils.

    """
    tmp = []
    for o in L:
        if o[0][:5] != '33:33' and o[0][:8] != '01:00:5e' and o[0] != 'ff:ff:ff:ff:ff:ff':
            tmp += [o]
    return tmp


def search_cst(L, cst):
    """
    Fonction qui associe aux adresses MAC des appareils un constructeur.

    Parameters
    ----------
    L : Liste des appareils.
    cst: Liste des MAC des différents constructeurs.

    Returns
    -------
    Liste des appareils associés à leur constructeur.

    """
    for o in L:
        cpt = len(o)
        for c in cst:
            if c['oui'] == o[0][:8].upper():
                o += [['cst', c['companyName']]]
                break
        if len(o) == cpt:
            o += [['cst', 'Inconnu']]
    return L


""" Afficher liste objet """
def aff_list(L):
    for i in L:
        print(i)


def cap_tshark(timer):
    """
    Fonction qui réalise une capture tshark et réalise un fichier avec.

    Parameters
    ----------
    timer : int qui déterminera la durée de la capture.

    Returns
    -------
    None.

    """
    run(['tshark', '-i' , 'eth0', '-w', 'file_audit.pcap', '-a', 'duration:' + str(timer)])


def comp_ua_bdd(Lhttp, L):
    """
    Fonction qui appelle la recherche de failles pour chaque objets Ethernets
    ainsi que les appareils WIFI ayant émis des trames HTTP.

    Parameters
    ----------
    Lhttp : Liste des User-Agents émis par les appareils WIFI.
    L : Liste des appareils Ethernet.

    Returns
    -------
    Liste des appareils Ethernets associés à leur(s) faille(s) trouvvée(s) ainsi
    que la liste de(s) failles(s) pour les appareils WIFI.

    """
    print('\nWIFI: Recherche dans BDD USER AGENT\n')
    tmp = []
    for usag in Lhttp:
        application, os, vs_os, gen_os = search_bdd(usag)
        tmp += [[usag, [application, os, vs_os, gen_os]]]
    print('\nETH: Recherche dans BDD USER AGENT\n')
    for app in L:
        for info in app:
            if info[0] == 'UA':
                application, os, vs_os, gen_os = search_bdd(info[1])
                info += [['bdd', application, os, vs_os, gen_os]]
    return L, tmp


def extract_trame(file, access_p):
    """
    Fonction qui répertorie tout les objets Ethernets avec leurs différentes
    informations ainsi que les informations émises par les objeets WIFI.

    Parameters
    ----------
    file : fichier d'une capture réseau.
    access_p : Adresse MAC du point d'accès.

    Returns
    -------
    Liste des informations des appareils Ethernets, liste des informations DHCP
    des appareils WIFI, liste des informations HTTP des appareils WIFI ainsi
    que la liste des informations SSDP des appareils WIFI.

    """
    cap = ps.FileCapture(file, display_filter='mdns or ssdp or (udp.port==67 and udp.port==68) or dhcpv6 or http')
    cst = construct()
    L = list_obj(cap, access_p)
    L = supp_MAC(L)
    L = search_cst(L, cst)
    cap1 = ps.FileCapture(file, display_filter='udp.port==67 and udp.port==68')
    L, Ldhcp = list_op_dhcp(cap1, L, access_p)
    """ Afficher liste objet """
    print("Liste DHCP")
    # aff_list(L)
    # print('\nWIFI: ', Ldhcp, '\n\n')
    # aff_list(Ldhcp)
    # print(L2)
#################################################################################
    """Récupération des infos via SSDP"""
    cap2 = ps.FileCapture(file, display_filter='ssdp')
    L2, Lssdp = list_info_ssdp(cap2, L, access_p)

    """ Afficher liste objet """
    print("Liste SSDP")
    # aff_list(L)
    # print(L4)
#################################################################################
    """Récupération des infos via HTTP"""
    cap3 = ps.FileCapture(file, display_filter='http')
    L3, Lhttp = list_info_http(cap3, L2, access_p)

    """ Afficher liste objet """
    print("Liste HTTP")
    # aff_list(L)
    # print('\nWIFI', Lhttp, '\n\n')
    # aff_list(Lhttp)

    return L, Ldhcp, Lhttp, Lssdp
